import argparse
import json
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


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--python-exe",
        default=sys.executable,
        help="用于启动子流程的 Python 可执行文件路径",
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

    model_group = parser.add_argument_group("模型文件（可选）")
    model_group.add_argument("--preprocessor", default="", help="可选：指定 preprocessor.joblib 路径")
    model_group.add_argument("--model", default="", help="可选：指定 best_mlp.pth 路径")


def main() -> None:
    project_root = Path(__file__).resolve().parent

    parser = argparse.ArgumentParser(
        description="统一入口：启动抓包 + 自动检测整条工作流",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "示例:\n"
            "  python app.py --port 80 --capture-batch-size 4\n"
            "  python app.py --port 3000 --capture-batch-size 1\n"
            "  python app.py --interface WLAN --port 10086 --capture-batch-size 20\n"
            "  python app.py --only-detect --no-skip-existing-at-start\n"
            "  python app.py --only-capture --port 80\n"
        ),
    )
    add_arguments(parser)
    args = parser.parse_args()

    if args.only_capture and args.only_detect:
        parser.error("--only-capture 与 --only-detect 不能同时使用")

    args.project_root = project_root

    scripts_dir = (project_root / args.scripts_dir).resolve()
    input_dir = (project_root / args.input_dir).resolve()
    output_dir = (project_root / args.output_dir).resolve()
    runtime_dir = output_dir / "app_runtime"

    input_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)
    runtime_dir.mkdir(parents=True, exist_ok=True)

    if args.preprocessor:
        args.preprocessor = Path(args.preprocessor).resolve()
    else:
        args.preprocessor = None

    if args.model:
        args.model = Path(args.model).resolve()
    else:
        args.model = None

    ensure_scripts(
        scripts_dir,
        [
            "capture_http_request_batches.py",
            "run_demo_daemon.py",
            "demo_workflow.py",
        ],
    )

    run_capture = not args.only_detect
    run_daemon = not args.only_capture

    app_log = runtime_dir / "app.log"
    state_file = runtime_dir / "app_state.json"
    capture_stdout = runtime_dir / "capture_stdout.log"
    capture_stderr = runtime_dir / "capture_stderr.log"
    daemon_stdout = runtime_dir / "daemon_stdout.log"
    daemon_stderr = runtime_dir / "daemon_stderr.log"

    capture_cmd = build_capture_cmd(args, scripts_dir, input_dir) if run_capture else []
    daemon_cmd = build_daemon_cmd(args, scripts_dir, input_dir, output_dir) if run_daemon else []

    log("APP start", app_log)
    log(f"project_root={project_root}", app_log)
    log(f"scripts_dir={scripts_dir}", app_log)
    log(f"mode capture={run_capture} daemon={run_daemon}", app_log)
    if run_capture:
        log("capture cmd: " + " ".join(capture_cmd), app_log)
    if run_daemon:
        log("daemon  cmd: " + " ".join(daemon_cmd), app_log)

    capture_proc = None
    daemon_proc = None
    capture_out_f = capture_err_f = daemon_out_f = daemon_err_f = None

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

        runtime_state = {
            "started_at": now_iso(),
            "project_root": str(project_root),
            "scripts_dir": str(scripts_dir),
            "mode": {"capture": run_capture, "daemon": run_daemon},
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
            "app_log": str(app_log),
        }
        write_runtime_state(state_file, runtime_state)

        log("workflow is running; press Ctrl+C to stop all", app_log)

        while True:
            cap_rc = capture_proc.poll() if capture_proc else None
            dmn_rc = daemon_proc.poll() if daemon_proc else None

            cap_alive = capture_proc is not None and cap_rc is None
            dmn_alive = daemon_proc is not None and dmn_rc is None

            if run_capture and capture_proc and cap_rc is not None:
                log(f"capture exited rc={cap_rc}", app_log)
                if daemon_proc:
                    terminate_process(daemon_proc, "daemon", app_log)
                raise SystemExit(cap_rc)

            if run_daemon and daemon_proc and dmn_rc is not None:
                log(f"daemon exited rc={dmn_rc}", app_log)
                if capture_proc:
                    terminate_process(capture_proc, "capture", app_log)
                raise SystemExit(dmn_rc)

            if not cap_alive and not dmn_alive:
                break

            time.sleep(1)

    except KeyboardInterrupt:
        log("Ctrl+C received, stopping children", app_log)
    finally:
        terminate_process(capture_proc, "capture", app_log)
        terminate_process(daemon_proc, "daemon", app_log)

        if capture_out_f:
            capture_out_f.close()
        if capture_err_f:
            capture_err_f.close()
        if daemon_out_f:
            daemon_out_f.close()
        if daemon_err_f:
            daemon_err_f.close()

        log("APP stopped", app_log)


if __name__ == "__main__":
    main()
