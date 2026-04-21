import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional


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
        raise FileNotFoundError(f"缺少脚本: {missing}，请确认 scripts 目录完整")


def ensure_paths(paths: List[Path], hint: str = "") -> None:
    missing = [str(p) for p in paths if not p.exists()]
    if missing:
        extra = f"，{hint}" if hint else ""
        raise FileNotFoundError(f"缺少文件: {missing}{extra}")


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
        raise FileNotFoundError(f"配置文件不存在: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError(f"配置文件不是有效 JSON: {path}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"配置文件格式错误(必须是 JSON object): {path}")
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


def build_capture_cmd(args, script_dir: Path, input_dir: Path) -> List[str]:
    cmd = [
        args.python_exe,
        str(script_dir / "capture_http_request_batches.py"),
        "--port",
        str(args.port),
        "--batch-size",
        str(args.capture_batch_size),
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
        "--seed-demo",
    ]
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
        help="用于启动子流程的 Python 可执行文件路径",
    )
    parser.add_argument(
        "--node-exe",
        default="node",
        help="用于启动前端服务的 Node.js 可执行文件路径",
    )

    mode_group = parser.add_argument_group("运行模式")
    mode_group.add_argument(
        "--only-capture",
        action="store_true",
        help="仅启动抓包写入，不启动自动检测守护",
    )
    mode_group.add_argument(
        "--only-detect",
        action="store_true",
        help="仅启动自动检测守护，不启动抓包",
    )

    io_group = parser.add_argument_group("目录与脚本")
    io_group.add_argument("--input-dir", default="input", help="抓包输出目录，同时也是检测监听目录")
    io_group.add_argument("--output-dir", default="output", help="流程输出目录")
    io_group.add_argument("--scripts-dir", default="scripts", help="脚本目录（默认 scripts）")
    io_group.add_argument("--db-config", default="", help="数据库配置 JSON 文件路径（可选，CLI 优先级更高）")

    capture_group = parser.add_argument_group("抓包设置")
    capture_group.add_argument("--port", type=int, default=80, help="监听 TCP 端口（可改成任意端口，如 3000/10086）")
    capture_group.add_argument(
        "--decode-http-port",
        type=int,
        default=None,
        help="强制按 HTTP 解码的端口；默认与 --port 相同",
    )
    capture_group.add_argument("--interface", default="", help="网卡关键字，如 WLAN / Wi-Fi")
    capture_group.add_argument(
        "--capture-batch-size",
        type=int,
        default=4,
        help="每累计多少条完整 HTTP 请求/响应写一个 1.1.n.txt",
    )

    detect_group = parser.add_argument_group("自动检测设置")
    detect_group.add_argument("--poll-seconds", type=int, default=5, help="守护轮询间隔（秒）")
    detect_group.add_argument("--stable-seconds", type=int, default=3, help="文件稳定判定时间（秒）")
    detect_group.add_argument("--retry-cooldown", type=int, default=30, help="失败后重试冷却时间（秒）")
    detect_group.add_argument("--label-threshold", type=float, default=0.35, help="模型标签阈值")
    detect_group.add_argument("--top-k", type=int, default=3, help="每个文件保留的候选数量")
    detect_group.add_argument("--export-min-score", type=float, default=0.3, help="导出到 result 的最低 raw_score")

    behavior_group = parser.add_argument_group("导出行为")
    behavior_group.add_argument(
        "--skip-existing-at-start",
        dest="skip_existing_at_start",
        action="store_true",
        help="启动时跳过当前已存在的 input 文件，仅处理后续新增",
    )
    behavior_group.add_argument(
        "--no-skip-existing-at-start",
        dest="skip_existing_at_start",
        action="store_false",
        help="启动后也会处理当前已存在的 input 文件",
    )
    parser.set_defaults(skip_existing_at_start=True)

    behavior_group.add_argument(
        "--update-existing-export",
        dest="update_existing_export",
        action="store_true",
        help="导出到 result 时，若 file_id+seq_id 已存在则覆盖更新",
    )
    behavior_group.add_argument(
        "--no-update-existing-export",
        dest="update_existing_export",
        action="store_false",
        help="导出到 result 时，已存在则跳过",
    )
    parser.set_defaults(update_existing_export=True)

    llm_group = parser.add_argument_group("LLM 分析守护（默认启用）")
    llm_group.add_argument(
        "--enable-llm",
        dest="enable_llm",
        action="store_true",
        help="启动 llm_analyzer_daemon，自动分析 result/b.n",
    )
    llm_group.add_argument(
        "--no-llm",
        dest="enable_llm",
        action="store_false",
        help="不启动 llm_analyzer_daemon",
    )
    parser.set_defaults(enable_llm=True)
    llm_group.add_argument("--llm-result-dir", default="result", help="LLM 监听的 result 目录")
    llm_group.add_argument("--llm-model", default="qwen3:8b", help="Ollama 模型名")
    llm_group.add_argument("--ollama-url", default="http://127.0.0.1:11434", help="Ollama 服务地址")
    llm_group.add_argument("--llm-prompt", default="llm/prompts/system_prompt.txt", help="系统提示词路径")
    llm_group.add_argument("--llm-schema", default="llm/schemas/analysis.schema.json", help="JSON schema 路径")
    llm_group.add_argument("--llm-poll-seconds", type=int, default=5, help="LLM 守护轮询间隔（秒）")
    llm_group.add_argument("--llm-timeout-sec", type=int, default=300, help="单条 LLM 请求超时（秒）")
    llm_group.add_argument("--llm-num-ctx", type=int, default=1024, help="Ollama num_ctx")
    llm_group.add_argument("--llm-num-gpu", type=int, default=0, help="Ollama num_gpu，0=CPU 更稳")
    llm_group.add_argument("--llm-temperature", type=float, default=0.2, help="LLM 采样温度")
    llm_group.add_argument("--llm-max-cases", type=int, default=0, help="每轮最多处理多少 case，0=不限制")

    db_group = parser.add_argument_group("结果入库守护（默认启用）")
    db_group.add_argument(
        "--enable-db",
        dest="enable_db",
        action="store_true",
        help="启动 result_db_daemon，监听 result 并自动入库数据库",
    )
    db_group.add_argument(
        "--no-db",
        dest="enable_db",
        action="store_false",
        help="不启动 result_db_daemon",
    )
    parser.set_defaults(enable_db=True)
    db_group.add_argument("--db-result-dir", default="result", help="DB 守护监听的 result 目录")
    db_group.add_argument("--db-backend", choices=["sqlite", "mysql"], default="mysql", help="DB 后端类型")
    db_group.add_argument("--db-path", default="result/result_cases.db", help="sqlite 模式下的 db 文件路径")
    db_group.add_argument("--mysql-host", default="127.0.0.1", help="MySQL 主机")
    db_group.add_argument("--mysql-port", type=int, default=3306, help="MySQL 端口")
    db_group.add_argument("--mysql-user", default="root", help="MySQL 用户名")
    db_group.add_argument("--mysql-password", default="123456", help="MySQL 密码")
    db_group.add_argument("--mysql-database", default="traffic_pipeline", help="MySQL 数据库名")
    db_group.add_argument("--db-poll-seconds", type=int, default=5, help="DB 守护轮询间隔（秒）")
    db_group.add_argument("--db-state-file", default="output/result_db_daemon_state.json", help="DB 守护状态文件")
    db_group.add_argument("--db-log-file", default="output/result_db_daemon.log", help="DB 守护日志文件")

    api_group = parser.add_argument_group("前端API服务（默认启用）")
    api_group.add_argument(
        "--enable-api",
        dest="enable_api",
        action="store_true",
        help="启动 dashboard_api_server.py（Flask，默认3049）",
    )
    api_group.add_argument(
        "--no-api",
        dest="enable_api",
        action="store_false",
        help="不启动 dashboard_api_server.py",
    )
    parser.set_defaults(enable_api=True)
    api_group.add_argument("--api-host", default="127.0.0.1", help="Flask API 绑定地址")
    api_group.add_argument("--api-port", type=int, default=3049, help="Flask API 端口")

    dashboard_group = parser.add_argument_group("前端大屏服务（默认启用）")
    dashboard_group.add_argument(
        "--enable-dashboard",
        dest="enable_dashboard",
        action="store_true",
        help="启动 Node.js 大屏服务（默认1145）",
    )
    dashboard_group.add_argument(
        "--no-dashboard",
        dest="enable_dashboard",
        action="store_false",
        help="不启动 Node.js 大屏服务",
    )
    parser.set_defaults(enable_dashboard=True)
    dashboard_group.add_argument("--dashboard-host", default="0.0.0.0", help="大屏服务绑定地址")
    dashboard_group.add_argument("--dashboard-port", type=int, default=1145, help="大屏服务端口")
    dashboard_group.add_argument(
        "--dashboard-server-script",
        default="frontend_dashboard/server.js",
        help="大屏 Node 启动脚本路径",
    )
    dashboard_group.add_argument(
        "--dashboard-api-base",
        default="",
        help="大屏前端代理上游API地址，留空时自动使用 http://127.0.0.1:<api-port>",
    )

    model_group = parser.add_argument_group("模型文件（可选）")
    model_group.add_argument("--preprocessor", default="", help="可选：指定 preprocessor.joblib 路径")
    model_group.add_argument("--model", default="", help="可选：指定 best_mlp.pth 路径")


def main() -> None:
    project_root = Path(__file__).resolve().parent

    parser = argparse.ArgumentParser(
        description="统一入口：启动抓包 + 自动检测 + LLM 分析 + DB 入库 + API + 大屏整条工作流",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "示例:\n"
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

    if args.only_capture and args.only_detect:
        parser.error("--only-capture 与 --only-detect 不能同时使用")

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

    dashboard_server = (project_root / args.dashboard_server_script).resolve()

    required_scripts = [
        "capture_http_request_batches.py",
        "run_demo_daemon.py",
        "demo_workflow.py",
    ]
    if run_llm:
        required_scripts.append("llm_analyzer_daemon.py")
    if run_db:
        required_scripts.extend(["result_db_daemon.py", "build_result_db.py"])
    if run_api:
        required_scripts.append("dashboard_api_server.py")
    ensure_scripts(scripts_dir, required_scripts)
    if run_dashboard:
        ensure_paths([dashboard_server], hint="请确认前端目录 frontend_dashboard 已存在")

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

    capture_cmd = build_capture_cmd(args, scripts_dir, input_dir) if run_capture else []
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
