import argparse
import ctypes
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional


def is_windows_admin() -> bool:
    if os.name != "nt":
        return True
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_self_as_admin(cwd: Path) -> bool:
    if os.name != "nt":
        return False
    params = subprocess.list2cmdline([str(Path(__file__).resolve())] + sys.argv[1:])
    try:
        rc = ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            sys.executable,
            params,
            str(cwd),
            1,
        )
    except Exception:
        return False
    return int(rc) > 32


def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def log(msg: str, log_path: Path) -> None:
    line = f"[{now_iso()}] {msg}"
    print(line, flush=True)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as f:
        f.write(line + "\n")


def ensure_scripts(script_dir: Path, script_names: List[str]) -> None:
    missing = [name for name in script_names if not (script_dir / name).exists()]
    if missing:
        raise FileNotFoundError(f"缂哄皯鑴氭湰: {missing}锛岃纭 scripts 鐩綍瀹屾暣")


def ensure_paths(paths: List[Path], hint: str = "") -> None:
    missing = [str(p) for p in paths if not p.exists()]
    if missing:
        extra = f", {hint}" if hint else ""
        raise FileNotFoundError(f"缂哄皯鏂囦欢: {missing}{extra}")


def terminate_process(proc: Optional[subprocess.Popen], name: str, log_path: Path) -> None:
    if proc is None or proc.poll() is not None:
        return
    try:
        log(f"stopping {name} pid={proc.pid}", log_path)
        proc.terminate()
        proc.wait(timeout=8)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def write_runtime_state(path: Path, state: Dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")


def read_json_config(path: Path) -> Dict:
    if not path.exists():
        raise FileNotFoundError(f"閰嶇疆鏂囦欢涓嶅瓨鍦? {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError(f"閰嶇疆鏂囦欢涓嶆槸鏈夋晥 JSON: {path}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"閰嶇疆鏂囦欢鏍煎紡閿欒(蹇呴』鏄?JSON object): {path}")
    return data


def apply_db_config(args, parser: argparse.ArgumentParser, project_root: Path) -> None:
    db_cfg_text = (getattr(args, "db_config", "") or "").strip()
    if not db_cfg_text:
        return

    db_cfg_path = Path(db_cfg_text)
    if not db_cfg_path.is_absolute():
        db_cfg_path = (project_root / db_cfg_path).resolve()
    cfg = read_json_config(db_cfg_path)
    mysql_cfg = cfg.get("mysql") if isinstance(cfg.get("mysql"), dict) else cfg

    defaults = {
        "db_backend": parser.get_default("db_backend"),
        "db_path": parser.get_default("db_path"),
        "mysql_host": parser.get_default("mysql_host"),
        "mysql_port": parser.get_default("mysql_port"),
        "mysql_user": parser.get_default("mysql_user"),
        "mysql_password": parser.get_default("mysql_password"),
        "mysql_database": parser.get_default("mysql_database"),
    }

    if getattr(args, "db_backend", None) == defaults["db_backend"] and cfg.get("db_backend") in {"sqlite", "mysql"}:
        args.db_backend = str(cfg["db_backend"])
    if getattr(args, "db_path", None) == defaults["db_path"] and isinstance(cfg.get("db_path"), str):
        args.db_path = cfg["db_path"]

    if getattr(args, "mysql_host", None) == defaults["mysql_host"] and isinstance(mysql_cfg.get("host"), str):
        args.mysql_host = mysql_cfg["host"]
    if getattr(args, "mysql_port", None) == defaults["mysql_port"] and mysql_cfg.get("port") is not None:
        args.mysql_port = int(mysql_cfg["port"])
    if getattr(args, "mysql_user", None) == defaults["mysql_user"] and isinstance(mysql_cfg.get("user"), str):
        args.mysql_user = mysql_cfg["user"]
    if getattr(args, "mysql_password", None) == defaults["mysql_password"] and isinstance(
        mysql_cfg.get("password"), str
    ):
        args.mysql_password = mysql_cfg["password"]
    if getattr(args, "mysql_database", None) == defaults["mysql_database"] and isinstance(
        mysql_cfg.get("database"), str
    ):
        args.mysql_database = mysql_cfg["database"]


def parse_ports_text(text: str, fallback: List[int]) -> List[int]:
    raw = (text or "").strip()
    if not raw:
        return [int(x) for x in fallback]
    parts = [x for x in re.split(r"[\s,]+", raw) if x]
    if not parts:
        return [int(x) for x in fallback]
    ports: List[int] = []
    seen = set()
    for part in parts:
        if not part.isdigit():
            raise ValueError(f"invalid port token: {part}")
        port = int(part)
        if port < 1 or port > 65535:
            raise ValueError(f"invalid port range: {port}")
        if port in seen:
            continue
        seen.add(port)
        ports.append(port)
    if not ports:
        return [int(x) for x in fallback]
    return ports


def load_capture_runtime_config(args, fallback_ports: List[int], fallback_batch_size: int) -> Dict:
    cfg = {
        "ports": [int(x) for x in fallback_ports],
        "batch_size": int(fallback_batch_size),
        "source": "cli",
        "error": "",
    }

    if not getattr(args, "capture_use_db_config", True):
        return cfg
    if str(getattr(args, "db_backend", "")).lower() != "mysql":
        return cfg

    try:
        import pymysql
    except Exception as exc:  # noqa: BLE001
        cfg["error"] = f"pymysql_import_failed: {exc}"
        return cfg

    try:
        conn = pymysql.connect(
            host=args.mysql_host,
            port=int(args.mysql_port),
            user=args.mysql_user,
            password=args.mysql_password,
            database=args.mysql_database,
            charset="utf8mb4",
            cursorclass=pymysql.cursors.DictCursor,
            autocommit=True,
        )
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT config_key, config_value
                    FROM demo_system_config
                    WHERE config_key IN ('monitor_ports', 'capture_batch_size')
                    """
                )
                rows = cur.fetchall()
        finally:
            conn.close()
    except Exception as exc:  # noqa: BLE001
        cfg["error"] = f"mysql_read_failed: {exc}"
        return cfg

    kv = {str(x.get("config_key", "")).strip(): str(x.get("config_value", "")).strip() for x in rows}
    try:
        if kv.get("monitor_ports"):
            cfg["ports"] = parse_ports_text(kv.get("monitor_ports", ""), fallback_ports)
    except Exception as exc:  # noqa: BLE001
        cfg["error"] = f"invalid_monitor_ports: {exc}"
        return cfg

    if kv.get("capture_batch_size"):
        try:
            batch = int(kv["capture_batch_size"])
            if 1 <= batch <= 128:
                cfg["batch_size"] = batch
            else:
                cfg["error"] = f"invalid_capture_batch_size: {batch}"
                return cfg
        except Exception as exc:  # noqa: BLE001
            cfg["error"] = f"invalid_capture_batch_size: {exc}"
            return cfg

    cfg["source"] = "db"
    return cfg


def build_capture_cmd(
    args,
    script_dir: Path,
    input_dir: Path,
    monitor_ports: Optional[List[int]] = None,
    batch_size: Optional[int] = None,
) -> List[str]:
    ports = list(monitor_ports or [args.port])
    if not ports:
        ports = [args.port]
    batch = int(batch_size if batch_size is not None else args.capture_batch_size)
    cmd = [
        args.python_exe,
        str(script_dir / "capture_http_request_batches.py"),
        "--port",
        str(ports[0]),
        "--ports",
        ",".join(str(p) for p in ports),
        "--batch-size",
        str(batch),
        "--input-dir",
        str(input_dir),
    ]
    if args.interface:
        cmd.extend(["--interface", args.interface])
    if args.decode_http_port is not None:
        cmd.extend(["--decode-http-port", str(args.decode_http_port)])
    return cmd


def build_daemon_cmd(args, script_dir: Path, input_dir: Path, output_dir: Path) -> List[str]:
    cmd = [
        args.python_exe,
        str(script_dir / "run_demo_daemon.py"),
        "--project-root",
        str(args.project_root),
        "--input-dir",
        str(input_dir),
        "--output-dir",
        str(output_dir),
        "--demo-script",
        str(script_dir / "demo_workflow.py"),
        "--poll-seconds",
        str(args.poll_seconds),
        "--stable-seconds",
        str(args.stable_seconds),
        "--file-order",
        str(args.detect_file_order),
        "--retry-cooldown",
        str(args.retry_cooldown),
        "--label-threshold",
        str(args.label_threshold),
        "--top-k",
        str(args.top_k),
        "--export-min-score",
        str(args.export_min_score),
    ]

    if args.skip_existing_at_start:
        cmd.append("--skip-existing-at-start")
    if args.update_existing_export:
        cmd.append("--update-existing-export")
    if args.preprocessor:
        cmd.extend(["--preprocessor", str(args.preprocessor)])
    if args.model:
        cmd.extend(["--model", str(args.model)])

    return cmd


def build_llm_cmd(args, script_dir: Path) -> List[str]:
    cmd = [
        args.python_exe,
        str(script_dir / "llm_analyzer_daemon.py"),
        "--result-dir",
        args.llm_result_dir,
        "--input-dir",
        args.input_dir,
        "--model",
        args.llm_model,
        "--ollama-url",
        args.ollama_url,
        "--prompt",
        args.llm_prompt,
        "--schema",
        args.llm_schema,
        "--poll-seconds",
        str(args.llm_poll_seconds),
        "--timeout-sec",
        str(args.llm_timeout_sec),
        "--num-ctx",
        str(args.llm_num_ctx),
        "--num-gpu",
        str(args.llm_num_gpu),
        "--temperature",
        str(args.llm_temperature),
        "--max-cases",
        str(args.llm_max_cases),
    ]
    if args.rag_enable:
        cmd.append("--rag-enable")
    else:
        cmd.append("--no-rag")
    cmd.extend(
        [
            "--rag-db-path",
            args.rag_db_path,
            "--rag-seed-file",
            args.rag_seed_file,
            "--rag-top-k",
            str(args.rag_top_k),
            "--rag-max-chars",
            str(args.rag_max_chars),
        ]
    )
    if args.rag_auto_build:
        cmd.append("--rag-auto-build")
    else:
        cmd.append("--no-rag-auto-build")
    return cmd


def build_db_cmd(args, script_dir: Path) -> List[str]:
    cmd = [
        args.python_exe,
        str(script_dir / "result_db_daemon.py"),
        "--result-dir",
        args.db_result_dir,
        "--backend",
        args.db_backend,
        "--db-path",
        args.db_path,
        "--mysql-host",
        args.mysql_host,
        "--mysql-port",
        str(args.mysql_port),
        "--mysql-user",
        args.mysql_user,
        "--mysql-password",
        args.mysql_password,
        "--mysql-database",
        args.mysql_database,
        "--poll-seconds",
        str(args.db_poll_seconds),
        "--state-file",
        args.db_state_file,
        "--log-file",
        args.db_log_file,
    ]
    return cmd


def build_api_cmd(args, script_dir: Path) -> List[str]:
    cmd = [
        args.python_exe,
        str(script_dir / "dashboard_api_server.py"),
        "--host",
        args.api_host,
        "--port",
        str(args.api_port),
        "--mysql-host",
        args.mysql_host,
        "--mysql-port",
        str(args.mysql_port),
        "--mysql-user",
        args.mysql_user,
        "--mysql-password",
        args.mysql_password,
        "--mysql-database",
        args.mysql_database,
        "--rag-db-path",
        args.rag_db_path,
        "--rag-seed-file",
        args.rag_seed_file,
    ]
    if args.api_seed_demo:
        cmd.append("--seed-demo")
    return cmd


def build_dashboard_cmd(args, dashboard_server: Path) -> List[str]:
    cmd = [
        args.node_exe,
        str(dashboard_server),
    ]
    return cmd


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--python-exe",
        default=sys.executable,
        help="鐢ㄤ簬鍚姩瀛愭祦绋嬬殑 Python 鍙墽琛屾枃浠惰矾寰?,
    )
    parser.add_argument(
        "--node-exe",
        default="node",
        help="鐢ㄤ簬鍚姩鍓嶇鏈嶅姟鐨?Node.js 鍙墽琛屾枃浠惰矾寰?,
    )
    parser.add_argument(
        "--auto-elevate",
        dest="auto_elevate",
        action="store_true",
        help="Windows 涓嬭嫢褰撳墠涓嶆槸绠＄悊鍛樻潈闄愶紝鑷姩寮瑰嚭 UAC 骞舵彁鏉冮噸鍚?app.py",
    )
    parser.add_argument(
        "--no-auto-elevate",
        dest="auto_elevate",
        action="store_false",
        help="鍏抽棴 Windows 鑷姩鎻愭潈",
    )
    parser.set_defaults(auto_elevate=True)

    mode_group = parser.add_argument_group("杩愯妯″紡")
    mode_group.add_argument(
        "--only-capture",
        action="store_true",
        help="浠呭惎鍔ㄦ姄鍖呭啓鍏ワ紝涓嶅惎鍔ㄨ嚜鍔ㄦ娴嬪畧鎶?,
    )
    mode_group.add_argument(
        "--only-detect",
        action="store_true",
        help="浠呭惎鍔ㄨ嚜鍔ㄦ娴嬪畧鎶わ紝涓嶅惎鍔ㄦ姄鍖?,
    )

    io_group = parser.add_argument_group("鐩綍涓庤剼鏈?)
    io_group.add_argument("--input-dir", default="input", help="鎶撳寘杈撳嚭鐩綍锛屽悓鏃朵篃鏄娴嬬洃鍚洰褰?)
    io_group.add_argument("--output-dir", default="output", help="娴佺▼杈撳嚭鐩綍")
    io_group.add_argument("--scripts-dir", default="scripts", help="鑴氭湰鐩綍锛堥粯璁?scripts锛?)
    io_group.add_argument("--db-config", default="", help="鏁版嵁搴撻厤缃?JSON 鏂囦欢璺緞锛堝彲閫夛紝CLI 浼樺厛绾ф洿楂橈級")

    capture_group = parser.add_argument_group("鎶撳寘璁剧疆")
    capture_group.add_argument("--port", type=int, default=80, help="鐩戝惉 TCP 绔彛锛堝彲鏀规垚浠绘剰绔彛锛屽 3000/10086锛?)
    capture_group.add_argument("--ports", default="", help="鐩戝惉绔彛鍒楄〃锛岄€楀彿鍒嗛殧锛涗负绌哄垯浠呯洃鍚?--port")
    capture_group.add_argument(
        "--decode-http-port",
        type=int,
        default=None,
        help="寮哄埗鎸?HTTP 瑙ｇ爜鐨勭鍙ｏ紱榛樿涓?--port 鐩稿悓",
    )
    capture_group.add_argument("--interface", default="", help="缃戝崱鍏抽敭瀛楋紝濡?WLAN / Wi-Fi")
    capture_group.add_argument(
        "--capture-batch-size",
        type=int,
        default=4,
        help="姣忕疮璁″灏戞潯瀹屾暣 HTTP 璇锋眰/鍝嶅簲鍐欎竴涓?1.1.n.txt",
    )
    capture_group.add_argument("--capture-config-poll-seconds", type=int, default=5, help="鎶撳寘閰嶇疆鐑洿鏂拌疆璇㈤棿闅旓紙绉掞級")
    capture_group.add_argument(
        "--capture-use-db-config",
        dest="capture_use_db_config",
        action="store_true",
        help="浼樺厛璇诲彇鏁版嵁搴?demo_system_config 涓殑 monitor_ports/capture_batch_size",
    )
    capture_group.add_argument(
        "--no-capture-use-db-config",
        dest="capture_use_db_config",
        action="store_false",
        help="浠呬娇鐢?CLI 鎶撳寘鍙傛暟锛屼笉璇诲彇鏁版嵁搴撴姄鍖呴厤缃?,
    )
    parser.set_defaults(capture_use_db_config=True)

    detect_group = parser.add_argument_group("鑷姩妫€娴嬭缃?)
    detect_group.add_argument("--poll-seconds", type=int, default=5, help="瀹堟姢杞闂撮殧锛堢锛?)
    detect_group.add_argument("--stable-seconds", type=int, default=3, help="鏂囦欢绋冲畾鍒ゅ畾鏃堕棿锛堢锛?)
    detect_group.add_argument(
        "--detect-file-order",
        choices=["newest", "oldest"],
        default="newest",
        help="妫€娴嬪鐞嗛『搴忥細newest=鏂版枃浠朵紭鍏堬紝oldest=鏃ф枃浠朵紭鍏?,
    )
    detect_group.add_argument("--retry-cooldown", type=int, default=30, help="澶辫触鍚庨噸璇曞喎鍗存椂闂达紙绉掞級")
    detect_group.add_argument("--label-threshold", type=float, default=0.46, help="妯″瀷鏍囩闃堝€?)
    detect_group.add_argument("--top-k", type=int, default=3, help="姣忎釜鏂囦欢淇濈暀鐨勫€欓€夋暟閲?)
    detect_group.add_argument("--export-min-score", type=float, default=0.3, help="瀵煎嚭鍒?result 鐨勬渶浣?raw_score")

    behavior_group = parser.add_argument_group("瀵煎嚭琛屼负")
    behavior_group.add_argument(
        "--skip-existing-at-start",
        dest="skip_existing_at_start",
        action="store_true",
        help="鍚姩鏃惰烦杩囧綋鍓嶅凡瀛樺湪鐨?input 鏂囦欢锛屼粎澶勭悊鍚庣画鏂板",
    )
    behavior_group.add_argument(
        "--no-skip-existing-at-start",
        dest="skip_existing_at_start",
        action="store_false",
        help="鍚姩鍚庝篃浼氬鐞嗗綋鍓嶅凡瀛樺湪鐨?input 鏂囦欢",
    )
    parser.set_defaults(skip_existing_at_start=True)

    behavior_group.add_argument(
        "--update-existing-export",
        dest="update_existing_export",
        action="store_true",
        help="瀵煎嚭鍒?result 鏃讹紝鑻?file_id+seq_id 宸插瓨鍦ㄥ垯瑕嗙洊鏇存柊",
    )
    behavior_group.add_argument(
        "--no-update-existing-export",
        dest="update_existing_export",
        action="store_false",
        help="瀵煎嚭鍒?result 鏃讹紝宸插瓨鍦ㄥ垯璺宠繃",
    )
    parser.set_defaults(update_existing_export=True)

    llm_group = parser.add_argument_group("LLM 鍒嗘瀽瀹堟姢锛堥粯璁ゅ惎鐢級")
    llm_group.add_argument(
        "--enable-llm",
        dest="enable_llm",
        action="store_true",
        help="鍚姩 llm_analyzer_daemon锛岃嚜鍔ㄥ垎鏋?result/b.n",
    )
    llm_group.add_argument(
        "--no-llm",
        dest="enable_llm",
        action="store_false",
        help="涓嶅惎鍔?llm_analyzer_daemon",
    )
    parser.set_defaults(enable_llm=True)
    llm_group.add_argument("--llm-result-dir", default="result", help="LLM 鐩戝惉鐨?result 鐩綍")
    llm_group.add_argument("--llm-model", default="qwen3:8b", help="Ollama 妯″瀷鍚?)
    llm_group.add_argument("--ollama-url", default="http://127.0.0.1:11434", help="Ollama 鏈嶅姟鍦板潃")
    llm_group.add_argument("--llm-prompt", default="llm/prompts/system_prompt.txt", help="绯荤粺鎻愮ず璇嶈矾寰?)
    llm_group.add_argument("--llm-schema", default="llm/schemas/analysis.schema.json", help="JSON schema 璺緞")
    llm_group.add_argument("--llm-poll-seconds", type=int, default=5, help="LLM 瀹堟姢杞闂撮殧锛堢锛?)
    llm_group.add_argument("--llm-timeout-sec", type=int, default=300, help="鍗曟潯 LLM 璇锋眰瓒呮椂锛堢锛?)
    llm_group.add_argument("--llm-num-ctx", type=int, default=1024, help="Ollama num_ctx")
    llm_group.add_argument("--llm-num-gpu", type=int, default=0, help="Ollama num_gpu锛?=CPU 鏇寸ǔ")
    llm_group.add_argument("--llm-temperature", type=float, default=0.2, help="LLM 閲囨牱娓╁害")
    llm_group.add_argument("--llm-max-cases", type=int, default=0, help="姣忚疆鏈€澶氬鐞嗗灏?case锛?=涓嶉檺鍒?)
    llm_group.add_argument("--rag-enable", dest="rag_enable", action="store_true", help="鍚敤 RAG 妫€绱㈠寮?)
    llm_group.add_argument("--no-rag", dest="rag_enable", action="store_false", help="鍏抽棴 RAG 妫€绱㈠寮?)
    parser.set_defaults(rag_enable=True)
    llm_group.add_argument("--rag-db-path", default="llm/rag/rag_knowledge.db", help="RAG sqlite db 鏂囦欢璺緞")
    llm_group.add_argument("--rag-seed-file", default="llm/rag/rag_seed.json", help="RAG seed JSON 鏂囦欢璺緞")
    llm_group.add_argument("--rag-top-k", type=int, default=3, help="RAG 姣忔妫€绱㈡潯鏁?)
    llm_group.add_argument("--rag-max-chars", type=int, default=3200, help="娉ㄥ叆 LLM 鐨?RAG 涓婁笅鏂囨渶澶у瓧绗︽暟")
    llm_group.add_argument("--rag-auto-build", dest="rag_auto_build", action="store_true", help="鑻?RAG db 涓嶅瓨鍦ㄥ垯鑷姩鏋勫缓")
    llm_group.add_argument("--no-rag-auto-build", dest="rag_auto_build", action="store_false", help="涓嶈嚜鍔ㄦ瀯寤?RAG db")
    parser.set_defaults(rag_auto_build=True)

    db_group = parser.add_argument_group("缁撴灉鍏ュ簱瀹堟姢锛堥粯璁ゅ惎鐢級")
    db_group.add_argument(
        "--enable-db",
        dest="enable_db",
        action="store_true",
        help="鍚姩 result_db_daemon锛岀洃鍚?result 骞惰嚜鍔ㄥ叆搴撴暟鎹簱",
    )
    db_group.add_argument(
        "--no-db",
        dest="enable_db",
        action="store_false",
        help="涓嶅惎鍔?result_db_daemon",
    )
    parser.set_defaults(enable_db=True)
    db_group.add_argument("--db-result-dir", default="result", help="DB 瀹堟姢鐩戝惉鐨?result 鐩綍")
    db_group.add_argument("--db-backend", choices=["sqlite", "mysql"], default="mysql", help="DB 鍚庣绫诲瀷")
    db_group.add_argument("--db-path", default="result/result_cases.db", help="sqlite 妯″紡涓嬬殑 db 鏂囦欢璺緞")
    db_group.add_argument("--mysql-host", default="127.0.0.1", help="MySQL 涓绘満")
    db_group.add_argument("--mysql-port", type=int, default=3306, help="MySQL 绔彛")
    db_group.add_argument("--mysql-user", default="root", help="MySQL 鐢ㄦ埛鍚?)
    db_group.add_argument("--mysql-password", default="123456", help="MySQL 瀵嗙爜")
    db_group.add_argument("--mysql-database", default="traffic_pipeline", help="MySQL 鏁版嵁搴撳悕")
    db_group.add_argument("--db-poll-seconds", type=int, default=5, help="DB 瀹堟姢杞闂撮殧锛堢锛?)
    db_group.add_argument("--db-state-file", default="output/result_db_daemon_state.json", help="DB 瀹堟姢鐘舵€佹枃浠?)
    db_group.add_argument("--db-log-file", default="output/result_db_daemon.log", help="DB 瀹堟姢鏃ュ織鏂囦欢")

    api_group = parser.add_argument_group("鍓嶇API鏈嶅姟锛堥粯璁ゅ惎鐢級")
    api_group.add_argument(
        "--enable-api",
        dest="enable_api",
        action="store_true",
        help="鍚姩 dashboard_api_server.py锛團lask锛岄粯璁?049锛?,
    )
    api_group.add_argument(
        "--no-api",
        dest="enable_api",
        action="store_false",
        help="涓嶅惎鍔?dashboard_api_server.py",
    )
    parser.set_defaults(enable_api=True)
    api_group.add_argument("--api-host", default="127.0.0.1", help="Flask API 缁戝畾鍦板潃")
    api_group.add_argument("--api-port", type=int, default=3049, help="Flask API 绔彛")
    api_group.add_argument(
        "--api-seed-demo",
        dest="api_seed_demo",
        action="store_true",
        help="鍚姩 API 鏃惰嚜鍔ㄥ啓鍏ユ紨绀烘暟鎹紙浠呯敤浜庣┖搴撳垵濮嬪寲锛?,
    )
    api_group.add_argument(
        "--no-api-seed-demo",
        dest="api_seed_demo",
        action="store_false",
        help="鍚姩 API 鏃朵笉鍐欏叆婕旂ず鏁版嵁",
    )
    parser.set_defaults(api_seed_demo=False)

    dashboard_group = parser.add_argument_group("鍓嶇澶у睆鏈嶅姟锛堥粯璁ゅ惎鐢級")
    dashboard_group.add_argument(
        "--enable-dashboard",
        dest="enable_dashboard",
        action="store_true",
        help="鍚姩 Node.js 澶у睆鏈嶅姟锛堥粯璁?145锛?,
    )
    dashboard_group.add_argument(
        "--no-dashboard",
        dest="enable_dashboard",
        action="store_false",
        help="涓嶅惎鍔?Node.js 澶у睆鏈嶅姟",
    )
    parser.set_defaults(enable_dashboard=True)
    dashboard_group.add_argument("--dashboard-host", default="0.0.0.0", help="澶у睆鏈嶅姟缁戝畾鍦板潃")
    dashboard_group.add_argument("--dashboard-port", type=int, default=1145, help="澶у睆鏈嶅姟绔彛")
    dashboard_group.add_argument(
        "--dashboard-server-script",
        default="frontend_dashboard/server.js",
        help="澶у睆 Node 鍚姩鑴氭湰璺緞",
    )
    dashboard_group.add_argument(
        "--dashboard-api-base",
        default="",
        help="澶у睆鍓嶇浠ｇ悊涓婃父API鍦板潃锛岀暀绌烘椂鑷姩浣跨敤 http://127.0.0.1:<api-port>",
    )

    model_group = parser.add_argument_group("妯″瀷鏂囦欢锛堝彲閫夛級")
    model_group.add_argument("--preprocessor", default="", help="鍙€夛細鎸囧畾 preprocessor.joblib 璺緞")
    model_group.add_argument("--model", default="", help="鍙€夛細鎸囧畾 best_mlp.pth 璺緞")


def main() -> None:
    project_root = Path(__file__).resolve().parent

    parser = argparse.ArgumentParser(
        description="缁熶竴鍏ュ彛锛氬惎鍔ㄦ姄鍖?+ 鑷姩妫€娴?+ LLM 鍒嗘瀽 + DB 鍏ュ簱 + API + 澶у睆鏁存潯宸ヤ綔娴?,
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "绀轰緥:\n"
            "  python app.py --port 80 --capture-batch-size 4\n"
            "  python app.py --port 3000 --capture-batch-size 1\n"
            "  python app.py --interface WLAN --port 10086 --capture-batch-size 20\n"
            "  python app.py --only-detect --no-skip-existing-at-start\n"
            "  python app.py --only-detect --no-llm --no-db --no-api --no-dashboard\n"
            "  python app.py --no-dashboard\n"
            "  python app.py --only-capture --port 80\n"
        ),
    )
    add_arguments(parser)
    args = parser.parse_args()
    apply_db_config(args, parser, project_root)

    if os.name == "nt" and args.auto_elevate and not is_windows_admin():
        print("[app] 妫€娴嬪埌褰撳墠涓嶆槸绠＄悊鍛樻潈闄愶紝姝ｅ湪鐢宠绠＄悊鍛樻潈闄愰噸鍚?..", flush=True)
        if relaunch_self_as_admin(project_root):
            return
        parser.error("绠＄悊鍛樻彁鏉冨け璐ユ垨琚彇娑堬紝璇峰彸閿互绠＄悊鍛樿韩浠借繍琛岀粓绔悗閲嶈瘯")

    if args.only_capture and args.only_detect:
        parser.error("--only-capture 涓?--only-detect 涓嶈兘鍚屾椂浣跨敤")

    args.project_root = project_root

    scripts_dir = (project_root / args.scripts_dir).resolve()
    input_dir = (project_root / args.input_dir).resolve()
    output_dir = (project_root / args.output_dir).resolve()
    result_dir = (project_root / args.llm_result_dir).resolve()
    runtime_dir = output_dir / "app_runtime"

    input_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)
    result_dir.mkdir(parents=True, exist_ok=True)
    runtime_dir.mkdir(parents=True, exist_ok=True)

    if args.preprocessor:
        args.preprocessor = Path(args.preprocessor).resolve()
    else:
        args.preprocessor = None

    if args.model:
        args.model = Path(args.model).resolve()
    else:
        args.model = None

    run_capture = not args.only_detect
    run_daemon = not args.only_capture
    run_llm = args.enable_llm and not args.only_capture
    run_db = args.enable_db and not args.only_capture
    run_api = args.enable_api and not args.only_capture
    run_dashboard = args.enable_dashboard and not args.only_capture

    try:
        cli_capture_ports = parse_ports_text(args.ports, [args.port])
    except Exception as exc:  # noqa: BLE001
        parser.error(f"--ports 鍙傛暟鏃犳晥: {exc}")
    cli_capture_batch_size = int(args.capture_batch_size)
    capture_runtime_cfg = {
        "ports": cli_capture_ports,
        "batch_size": cli_capture_batch_size,
        "source": "cli",
        "error": "",
    }
    capture_config_error_logged = ""
    if run_capture:
        capture_runtime_cfg = load_capture_runtime_config(args, cli_capture_ports, cli_capture_batch_size)
        if capture_runtime_cfg.get("error"):
            log(
                f"capture config load failed, fallback to CLI: {capture_runtime_cfg.get('error')}",
                output_dir / "app_runtime" / "app.log",
            )
            capture_runtime_cfg = {
                "ports": cli_capture_ports,
                "batch_size": cli_capture_batch_size,
                "source": "cli",
                "error": "",
            }
            capture_config_error_logged = "fallback_logged"

    dashboard_server = (project_root / args.dashboard_server_script).resolve()

    required_scripts = [
        "capture_http_request_batches.py",
        "run_demo_daemon.py",
        "demo_workflow.py",
    ]
    if run_llm:
        required_scripts.extend(["llm_analyzer_daemon.py", "build_rag_db.py"])
    if run_db:
        required_scripts.extend(["result_db_daemon.py", "build_result_db.py"])
    if run_api:
        required_scripts.append("dashboard_api_server.py")
    ensure_scripts(scripts_dir, required_scripts)
    if run_dashboard:
        ensure_paths([dashboard_server], hint="璇风‘璁ゅ墠绔洰褰?frontend_dashboard 宸插瓨鍦?)

    dashboard_api_base = args.dashboard_api_base.strip()
    if not dashboard_api_base:
        dashboard_api_base = f"http://127.0.0.1:{args.api_port}"

    app_log = runtime_dir / "app.log"
    state_file = runtime_dir / "app_state.json"
    capture_stdout = runtime_dir / "capture_stdout.log"
    capture_stderr = runtime_dir / "capture_stderr.log"
    daemon_stdout = runtime_dir / "daemon_stdout.log"
    daemon_stderr = runtime_dir / "daemon_stderr.log"
    llm_stdout = runtime_dir / "llm_stdout.log"
    llm_stderr = runtime_dir / "llm_stderr.log"
    db_stdout = runtime_dir / "db_stdout.log"
    db_stderr = runtime_dir / "db_stderr.log"
    api_stdout = runtime_dir / "api_stdout.log"
    api_stderr = runtime_dir / "api_stderr.log"
    dashboard_stdout = runtime_dir / "dashboard_stdout.log"
    dashboard_stderr = runtime_dir / "dashboard_stderr.log"

    capture_cmd = (
        build_capture_cmd(
            args,
            scripts_dir,
            input_dir,
            monitor_ports=capture_runtime_cfg["ports"],
            batch_size=capture_runtime_cfg["batch_size"],
        )
        if run_capture
        else []
    )
    daemon_cmd = build_daemon_cmd(args, scripts_dir, input_dir, output_dir) if run_daemon else []
    llm_cmd = build_llm_cmd(args, scripts_dir) if run_llm else []
    db_cmd = build_db_cmd(args, scripts_dir) if run_db else []
    api_cmd = build_api_cmd(args, scripts_dir) if run_api else []
    dashboard_cmd = build_dashboard_cmd(args, dashboard_server) if run_dashboard else []

    log("APP start", app_log)
    log(f"project_root={project_root}", app_log)
    log(f"scripts_dir={scripts_dir}", app_log)
    log(
        f"mode capture={run_capture} daemon={run_daemon} llm={run_llm} db={run_db} api={run_api} dashboard={run_dashboard}",
        app_log,
    )
    if run_capture:
        log("capture cmd: " + " ".join(capture_cmd), app_log)
        log(
            "capture config: "
            + f"source={capture_runtime_cfg.get('source')} "
            + f"ports={capture_runtime_cfg.get('ports')} "
            + f"batch_size={capture_runtime_cfg.get('batch_size')}",
            app_log,
        )
    if run_daemon:
        log("daemon  cmd: " + " ".join(daemon_cmd), app_log)
    if run_llm:
        log("llm     cmd: " + " ".join(llm_cmd), app_log)
    if run_db:
        log("db      cmd: " + " ".join(db_cmd), app_log)
    if run_api:
        log("api     cmd: " + " ".join(api_cmd), app_log)
    if run_dashboard:
        log("dashboard cmd: " + " ".join(dashboard_cmd), app_log)
        log(f"dashboard api base: {dashboard_api_base}", app_log)

    capture_proc = daemon_proc = llm_proc = db_proc = api_proc = dashboard_proc = None
    capture_out_f = capture_err_f = daemon_out_f = daemon_err_f = llm_out_f = llm_err_f = None
    db_out_f = db_err_f = api_out_f = api_err_f = dashboard_out_f = dashboard_err_f = None
    dashboard_env = dict()
    if run_dashboard:
        dashboard_env = dict(os.environ)
        dashboard_env["DASHBOARD_HOST"] = args.dashboard_host
        dashboard_env["DASHBOARD_PORT"] = str(args.dashboard_port)
        dashboard_env["API_BASE"] = dashboard_api_base

    try:
        if run_capture:
            capture_out_f = capture_stdout.open("a", encoding="utf-8")
            capture_err_f = capture_stderr.open("a", encoding="utf-8")
            capture_proc = subprocess.Popen(
                capture_cmd,
                cwd=str(project_root),
                stdout=capture_out_f,
                stderr=capture_err_f,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            log(f"capture started pid={capture_proc.pid}", app_log)

        if run_daemon:
            daemon_out_f = daemon_stdout.open("a", encoding="utf-8")
            daemon_err_f = daemon_stderr.open("a", encoding="utf-8")
            daemon_proc = subprocess.Popen(
                daemon_cmd,
                cwd=str(project_root),
                stdout=daemon_out_f,
                stderr=daemon_err_f,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            log(f"daemon  started pid={daemon_proc.pid}", app_log)

        if run_llm:
            llm_out_f = llm_stdout.open("a", encoding="utf-8")
            llm_err_f = llm_stderr.open("a", encoding="utf-8")
            llm_proc = subprocess.Popen(
                llm_cmd,
                cwd=str(project_root),
                stdout=llm_out_f,
                stderr=llm_err_f,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            log(f"llm     started pid={llm_proc.pid}", app_log)

        if run_db:
            db_out_f = db_stdout.open("a", encoding="utf-8")
            db_err_f = db_stderr.open("a", encoding="utf-8")
            db_proc = subprocess.Popen(
                db_cmd,
                cwd=str(project_root),
                stdout=db_out_f,
                stderr=db_err_f,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            log(f"db      started pid={db_proc.pid}", app_log)

        if run_api:
            api_out_f = api_stdout.open("a", encoding="utf-8")
            api_err_f = api_stderr.open("a", encoding="utf-8")
            api_proc = subprocess.Popen(
                api_cmd,
                cwd=str(project_root),
                stdout=api_out_f,
                stderr=api_err_f,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            log(f"api     started pid={api_proc.pid}", app_log)

        if run_dashboard:
            dashboard_out_f = dashboard_stdout.open("a", encoding="utf-8")
            dashboard_err_f = dashboard_stderr.open("a", encoding="utf-8")
            dashboard_proc = subprocess.Popen(
                dashboard_cmd,
                cwd=str(project_root),
                stdout=dashboard_out_f,
                stderr=dashboard_err_f,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=dashboard_env,
            )
            log(f"dashboard started pid={dashboard_proc.pid}", app_log)

        runtime_state = {
            "started_at": now_iso(),
            "project_root": str(project_root),
            "scripts_dir": str(scripts_dir),
            "mode": {
                "capture": run_capture,
                "daemon": run_daemon,
                "llm": run_llm,
                "db": run_db,
                "api": run_api,
                "dashboard": run_dashboard,
            },
            "capture": {
                "pid": capture_proc.pid if capture_proc else None,
                "cmd": capture_cmd,
                "config_source": capture_runtime_cfg.get("source"),
                "monitor_ports": capture_runtime_cfg.get("ports"),
                "batch_size": capture_runtime_cfg.get("batch_size"),
                "stdout": str(capture_stdout),
                "stderr": str(capture_stderr),
            },
            "daemon": {
                "pid": daemon_proc.pid if daemon_proc else None,
                "cmd": daemon_cmd,
                "stdout": str(daemon_stdout),
                "stderr": str(daemon_stderr),
            },
            "llm": {
                "pid": llm_proc.pid if llm_proc else None,
                "cmd": llm_cmd,
                "stdout": str(llm_stdout),
                "stderr": str(llm_stderr),
            },
            "db": {
                "pid": db_proc.pid if db_proc else None,
                "cmd": db_cmd,
                "stdout": str(db_stdout),
                "stderr": str(db_stderr),
            },
            "api": {
                "pid": api_proc.pid if api_proc else None,
                "cmd": api_cmd,
                "stdout": str(api_stdout),
                "stderr": str(api_stderr),
            },
            "dashboard": {
                "pid": dashboard_proc.pid if dashboard_proc else None,
                "cmd": dashboard_cmd,
                "stdout": str(dashboard_stdout),
                "stderr": str(dashboard_stderr),
                "url": f"http://127.0.0.1:{args.dashboard_port}",
                "api_base": dashboard_api_base,
            },
            "app_log": str(app_log),
        }
        write_runtime_state(state_file, runtime_state)

        capture_cfg_key = (
            f"ports={','.join(str(x) for x in capture_runtime_cfg.get('ports', []))}|"
            f"batch={capture_runtime_cfg.get('batch_size')}"
        )
        next_capture_cfg_check_ts = 0.0
        capture_cfg_poll_seconds = max(1, int(args.capture_config_poll_seconds))

        log("workflow is running; press Ctrl+C to stop all", app_log)

        while True:
            cap_rc = capture_proc.poll() if capture_proc else None
            dmn_rc = daemon_proc.poll() if daemon_proc else None
            llm_rc = llm_proc.poll() if llm_proc else None
            db_rc = db_proc.poll() if db_proc else None
            api_rc = api_proc.poll() if api_proc else None
            dashboard_rc = dashboard_proc.poll() if dashboard_proc else None

            cap_alive = capture_proc is not None and cap_rc is None
            dmn_alive = daemon_proc is not None and dmn_rc is None
            llm_alive = llm_proc is not None and llm_rc is None
            db_alive = db_proc is not None and db_rc is None
            api_alive = api_proc is not None and api_rc is None
            dashboard_alive = dashboard_proc is not None and dashboard_rc is None

            if run_capture and capture_proc and cap_rc is None and time.time() >= next_capture_cfg_check_ts:
                next_capture_cfg_check_ts = time.time() + capture_cfg_poll_seconds
                updated_cfg = load_capture_runtime_config(args, cli_capture_ports, cli_capture_batch_size)
                cfg_error = str(updated_cfg.get("error") or "")
                if cfg_error:
                    if cfg_error != capture_config_error_logged:
                        log(f"capture config reload failed, keep current: {cfg_error}", app_log)
                    capture_config_error_logged = cfg_error
                else:
                    capture_config_error_logged = ""
                    new_cfg_key = (
                        f"ports={','.join(str(x) for x in updated_cfg.get('ports', []))}|"
                        f"batch={updated_cfg.get('batch_size')}"
                    )
                    if new_cfg_key != capture_cfg_key:
                        new_capture_cmd = build_capture_cmd(
                            args,
                            scripts_dir,
                            input_dir,
                            monitor_ports=updated_cfg["ports"],
                            batch_size=updated_cfg["batch_size"],
                        )
                        log(
                            "capture config changed, restarting capture: "
                            + f"source={updated_cfg.get('source')} ports={updated_cfg.get('ports')} "
                            + f"batch_size={updated_cfg.get('batch_size')}",
                            app_log,
                        )
                        terminate_process(capture_proc, "capture", app_log)
                        capture_proc = subprocess.Popen(
                            new_capture_cmd,
                            cwd=str(project_root),
                            stdout=capture_out_f,
                            stderr=capture_err_f,
                            text=True,
                            encoding="utf-8",
                            errors="replace",
                        )
                        capture_cmd = new_capture_cmd
                        capture_runtime_cfg = updated_cfg
                        capture_cfg_key = new_cfg_key
                        runtime_state["capture"]["pid"] = capture_proc.pid
                        runtime_state["capture"]["cmd"] = capture_cmd
                        runtime_state["capture"]["config_source"] = capture_runtime_cfg.get("source")
                        runtime_state["capture"]["monitor_ports"] = capture_runtime_cfg.get("ports")
                        runtime_state["capture"]["batch_size"] = capture_runtime_cfg.get("batch_size")
                        write_runtime_state(state_file, runtime_state)
                        log(f"capture restarted pid={capture_proc.pid}", app_log)

            if run_capture and capture_proc and cap_rc is not None:
                log(f"capture exited rc={cap_rc}", app_log)
                if daemon_proc:
                    terminate_process(daemon_proc, "daemon", app_log)
                if llm_proc:
                    terminate_process(llm_proc, "llm", app_log)
                if db_proc:
                    terminate_process(db_proc, "db", app_log)
                if api_proc:
                    terminate_process(api_proc, "api", app_log)
                if dashboard_proc:
                    terminate_process(dashboard_proc, "dashboard", app_log)
                raise SystemExit(cap_rc)

            if run_daemon and daemon_proc and dmn_rc is not None:
                log(f"daemon exited rc={dmn_rc}", app_log)
                if capture_proc:
                    terminate_process(capture_proc, "capture", app_log)
                if llm_proc:
                    terminate_process(llm_proc, "llm", app_log)
                if db_proc:
                    terminate_process(db_proc, "db", app_log)
                if api_proc:
                    terminate_process(api_proc, "api", app_log)
                if dashboard_proc:
                    terminate_process(dashboard_proc, "dashboard", app_log)
                raise SystemExit(dmn_rc)

            if run_llm and llm_proc and llm_rc is not None:
                log(f"llm exited rc={llm_rc}", app_log)
                if capture_proc:
                    terminate_process(capture_proc, "capture", app_log)
                if daemon_proc:
                    terminate_process(daemon_proc, "daemon", app_log)
                if db_proc:
                    terminate_process(db_proc, "db", app_log)
                if api_proc:
                    terminate_process(api_proc, "api", app_log)
                if dashboard_proc:
                    terminate_process(dashboard_proc, "dashboard", app_log)
                raise SystemExit(llm_rc)

            if run_db and db_proc and db_rc is not None:
                log(f"db exited rc={db_rc}", app_log)
                if capture_proc:
                    terminate_process(capture_proc, "capture", app_log)
                if daemon_proc:
                    terminate_process(daemon_proc, "daemon", app_log)
                if llm_proc:
                    terminate_process(llm_proc, "llm", app_log)
                if api_proc:
                    terminate_process(api_proc, "api", app_log)
                if dashboard_proc:
                    terminate_process(dashboard_proc, "dashboard", app_log)
                raise SystemExit(db_rc)

            if run_api and api_proc and api_rc is not None:
                log(f"api exited rc={api_rc}", app_log)
                if capture_proc:
                    terminate_process(capture_proc, "capture", app_log)
                if daemon_proc:
                    terminate_process(daemon_proc, "daemon", app_log)
                if llm_proc:
                    terminate_process(llm_proc, "llm", app_log)
                if db_proc:
                    terminate_process(db_proc, "db", app_log)
                if dashboard_proc:
                    terminate_process(dashboard_proc, "dashboard", app_log)
                raise SystemExit(api_rc)

            if run_dashboard and dashboard_proc and dashboard_rc is not None:
                log(f"dashboard exited rc={dashboard_rc}", app_log)
                if capture_proc:
                    terminate_process(capture_proc, "capture", app_log)
                if daemon_proc:
                    terminate_process(daemon_proc, "daemon", app_log)
                if llm_proc:
                    terminate_process(llm_proc, "llm", app_log)
                if db_proc:
                    terminate_process(db_proc, "db", app_log)
                if api_proc:
                    terminate_process(api_proc, "api", app_log)
                raise SystemExit(dashboard_rc)

            if not cap_alive and not dmn_alive and not llm_alive and not db_alive and not api_alive and not dashboard_alive:
                break

            time.sleep(1)

    except KeyboardInterrupt:
        log("Ctrl+C received, stopping children", app_log)
    finally:
        terminate_process(capture_proc, "capture", app_log)
        terminate_process(daemon_proc, "daemon", app_log)
        terminate_process(llm_proc, "llm", app_log)
        terminate_process(db_proc, "db", app_log)
        terminate_process(api_proc, "api", app_log)
        terminate_process(dashboard_proc, "dashboard", app_log)

        if capture_out_f:
            capture_out_f.close()
        if capture_err_f:
            capture_err_f.close()
        if daemon_out_f:
            daemon_out_f.close()
        if daemon_err_f:
            daemon_err_f.close()
        if llm_out_f:
            llm_out_f.close()
        if llm_err_f:
            llm_err_f.close()
        if db_out_f:
            db_out_f.close()
        if db_err_f:
            db_err_f.close()
        if api_out_f:
            api_out_f.close()
        if api_err_f:
            api_err_f.close()
        if dashboard_out_f:
            dashboard_out_f.close()
        if dashboard_err_f:
            dashboard_err_f.close()

        log("APP stopped", app_log)


if __name__ == "__main__":
    main()



