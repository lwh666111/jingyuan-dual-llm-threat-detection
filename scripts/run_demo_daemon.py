import argparse
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple

FILE_PATTERN = re.compile(r"^1\.1\.(\d+)\.txt$")


def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def log(msg: str, log_file: Path) -> None:
    line = f"[{now_iso()}] {msg}"
    print(line, flush=True)
    log_file.parent.mkdir(parents=True, exist_ok=True)
    with log_file.open("a", encoding="utf-8") as f:
        f.write(line + "\n")


def load_state(path: Path) -> Dict:
    if not path.exists():
        return {
            "version": 1,
            "success": {},
            "failed": {},
            "ignored": {},
        }
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(state, dict):
            raise ValueError("invalid state object")
        state.setdefault("version", 1)
        state.setdefault("success", {})
        state.setdefault("failed", {})
        state.setdefault("ignored", {})
        return state
    except Exception:
        return {
            "version": 1,
            "success": {},
            "failed": {},
            "ignored": {},
        }


def save_state(path: Path, state: Dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")


def list_input_files(input_dir: Path) -> List[Tuple[int, Path]]:
    items: List[Tuple[int, Path]] = []
    for p in input_dir.glob("1.1.*.txt"):
        m = FILE_PATTERN.match(p.name)
        if not m:
            continue
        items.append((int(m.group(1)), p))
    items.sort(key=lambda x: x[0])
    return items


def is_file_stable(path: Path, stable_seconds: int) -> bool:
    if not path.exists():
        return False
    try:
        stat = path.stat()
    except OSError:
        return False
    age = time.time() - stat.st_mtime
    return age >= stable_seconds and stat.st_size > 0


def build_demo_command(args, input_path: Path) -> List[str]:
    cmd = [
        args.python_exe,
        str(args.demo_script),
        "--input-txt",
        str(input_path),
        "--label-threshold",
        str(args.label_threshold),
        "--top-k",
        str(args.top_k),
        "--export-min-score",
        str(args.export_min_score),
    ]
    if args.preprocessor:
        cmd.extend(["--preprocessor", str(args.preprocessor)])
    if args.model:
        cmd.extend(["--model", str(args.model)])
    if args.update_existing_export:
        cmd.append("--update-existing-export")
    return cmd


def should_retry_failed(failed_info: Dict, retry_cooldown: int) -> bool:
    if not failed_info:
        return True
    last_failed_at = failed_info.get("last_failed_at")
    if not last_failed_at:
        return True
    try:
        last_ts = datetime.fromisoformat(last_failed_at).timestamp()
    except Exception:
        return True
    return (time.time() - last_ts) >= retry_cooldown


def process_one(args, state: Dict, path: Path, idx: int, log_file: Path) -> bool:
    key = path.name
    success_info = state.get("success", {}).get(key)
    if success_info:
        return False
    ignored_info = state.get("ignored", {}).get(key)
    if ignored_info:
        return False

    failed_info = state.get("failed", {}).get(key, {})
    if args.max_fail_attempts > 0:
        failed_attempts = int(failed_info.get("attempts", 0))
        if failed_attempts >= args.max_fail_attempts:
            state.setdefault("ignored", {})[key] = {
                "index": idx,
                "path": str(path.resolve()),
                "ignored_at": now_iso(),
                "reason": "max_fail_attempts_reached",
                "attempts": failed_attempts,
            }
            state.setdefault("failed", {}).pop(key, None)
            save_state(args.state_file, state)
            log(
                f"SKIP #{idx}: {path.name} ignored after {failed_attempts} failed attempts",
                log_file,
            )
            return False

    if not should_retry_failed(failed_info, args.retry_cooldown):
        return False

    if not is_file_stable(path, args.stable_seconds):
        return False

    cmd = build_demo_command(args, path)
    log(f"START #{idx}: {path}", log_file)
    log("CMD: " + " ".join(cmd), log_file)

    result = subprocess.run(
        cmd,
        cwd=str(args.project_root),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    demo_log_dir = args.output_dir / "daemon_runs"
    demo_log_dir.mkdir(parents=True, exist_ok=True)
    run_log = demo_log_dir / f"{path.stem}.{now_iso().replace(':', '-')}.log"
    with run_log.open("w", encoding="utf-8") as f:
        f.write("[STDOUT]\n")
        f.write(result.stdout or "")
        f.write("\n\n[STDERR]\n")
        f.write(result.stderr or "")

    if result.returncode == 0:
        state.setdefault("success", {})[key] = {
            "index": idx,
            "path": str(path.resolve()),
            "processed_at": now_iso(),
            "run_log": str(run_log.resolve()),
        }
        state.setdefault("failed", {}).pop(key, None)
        save_state(args.state_file, state)
        log(f"DONE #{idx}: {path.name} -> success", log_file)
        return True

    fail_record = state.setdefault("failed", {}).get(key, {})
    attempts = int(fail_record.get("attempts", 0)) + 1
    state.setdefault("failed", {})[key] = {
        "index": idx,
        "path": str(path.resolve()),
        "attempts": attempts,
        "last_failed_at": now_iso(),
        "last_returncode": result.returncode,
        "run_log": str(run_log.resolve()),
    }
    if args.max_fail_attempts > 0 and attempts >= args.max_fail_attempts:
        state.setdefault("ignored", {})[key] = {
            "index": idx,
            "path": str(path.resolve()),
            "ignored_at": now_iso(),
            "reason": "max_fail_attempts_reached",
            "attempts": attempts,
            "last_returncode": result.returncode,
            "run_log": str(run_log.resolve()),
        }
        state.setdefault("failed", {}).pop(key, None)
    save_state(args.state_file, state)
    if args.max_fail_attempts > 0 and attempts >= args.max_fail_attempts:
        log(
            f"FAIL #{idx}: {path.name} rc={result.returncode} attempts={attempts} -> ignored",
            log_file,
        )
    else:
        log(f"FAIL #{idx}: {path.name} rc={result.returncode} attempts={attempts}", log_file)
    return True


def main() -> None:
    script_dir = Path(__file__).resolve().parent
    if (script_dir / "app.py").exists():
        project_root = script_dir
    elif (script_dir.parent / "app.py").exists():
        project_root = script_dir.parent
    else:
        project_root = script_dir

    parser = argparse.ArgumentParser(description="常驻监听 input/1.1.n.txt 并自动运行 demo_workflow.py")
    parser.add_argument("--project-root", default=str(project_root), help="项目根目录")
    parser.add_argument("--input-dir", default="input", help="监听目录")
    parser.add_argument("--output-dir", default="output", help="输出目录")
    parser.add_argument("--demo-script", default="scripts/demo_workflow.py", help="demo workflow 脚本路径")
    parser.add_argument("--state-file", default="output/demo_daemon_state.json", help="状态文件路径")
    parser.add_argument("--log-file", default="output/demo_daemon.log", help="守护日志路径")
    parser.add_argument("--poll-seconds", type=int, default=5, help="轮询间隔秒")
    parser.add_argument("--stable-seconds", type=int, default=3, help="文件静止判定秒")
    parser.add_argument("--retry-cooldown", type=int, default=30, help="失败重试冷却秒")
    parser.add_argument("--max-fail-attempts", type=int, default=5, help="单文件失败超过该次数后自动忽略；0=无限重试")
    parser.add_argument("--once", action="store_true", help="只扫描并处理一次后退出")
    parser.add_argument(
        "--skip-existing-at-start",
        action="store_true",
        help="启动时将当前已存在的 1.1.n.txt 标记为已处理，仅监听后续新文件",
    )

    parser.add_argument("--python-exe", default=sys.executable, help="调用 demo_workflow 的 Python")
    parser.add_argument("--preprocessor", default="", help="传给 demo_workflow 的 preprocessor 路径")
    parser.add_argument("--model", default="", help="传给 demo_workflow 的 model 路径")
    parser.add_argument("--label-threshold", type=float, default=0.35)
    parser.add_argument("--top-k", type=int, default=3)
    parser.add_argument("--export-min-score", type=float, default=0.3)
    parser.add_argument("--update-existing-export", action="store_true")

    args = parser.parse_args()

    args.project_root = Path(args.project_root).resolve()
    args.input_dir = (args.project_root / args.input_dir).resolve()
    args.output_dir = (args.project_root / args.output_dir).resolve()
    args.demo_script = (args.project_root / args.demo_script).resolve()
    args.state_file = (args.project_root / args.state_file).resolve()
    args.log_file = (args.project_root / args.log_file).resolve()

    if args.preprocessor:
        args.preprocessor = Path(args.preprocessor).resolve()
    else:
        args.preprocessor = None
    if args.model:
        args.model = Path(args.model).resolve()
    else:
        args.model = None

    if not args.demo_script.exists():
        raise FileNotFoundError(f"demo script 不存在: {args.demo_script}")

    args.input_dir.mkdir(parents=True, exist_ok=True)
    args.output_dir.mkdir(parents=True, exist_ok=True)

    state = load_state(args.state_file)

    if args.skip_existing_at_start and not state.get("success"):
        seeded = 0
        for idx, path in list_input_files(args.input_dir):
            key = path.name
            state.setdefault("success", {})[key] = {
                "index": idx,
                "path": str(path.resolve()),
                "processed_at": now_iso(),
                "seeded": True,
            }
            seeded += 1
        save_state(args.state_file, state)
        log(f"seeded existing files: {seeded}", args.log_file)

    log("DEMO daemon started", args.log_file)
    log(f"watch dir: {args.input_dir}", args.log_file)
    log(f"state file: {args.state_file}", args.log_file)

    while True:
        processed_in_round = 0
        files = list_input_files(args.input_dir)

        for idx, path in files:
            did = process_one(args, state, path, idx, args.log_file)
            if did:
                processed_in_round += 1

        if args.once:
            log(f"ONCE done. processed_in_round={processed_in_round}", args.log_file)
            break

        time.sleep(max(args.poll_seconds, 1))


if __name__ == "__main__":
    main()
