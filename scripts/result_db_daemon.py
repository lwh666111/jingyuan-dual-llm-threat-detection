import argparse
import hashlib
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List

from build_result_db import MySQLConfig, sync_result_to_db


def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def log(msg: str, log_file: Path) -> None:
    line = f"[{now_iso()}] {msg}"
    print(line, flush=True)
    log_file.parent.mkdir(parents=True, exist_ok=True)
    with log_file.open("a", encoding="utf-8") as f:
        f.write(line + "\n")


def read_state(path: Path) -> Dict:
    if not path.exists():
        return {"version": 1}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"version": 1}


def write_state(path: Path, state: Dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")


def collect_watch_files(result_dir: Path) -> List[Path]:
    files: List[Path] = []
    manifest = result_dir / "manifest.jsonl"
    if manifest.exists():
        files.append(manifest)

    case_dirs = [p for p in result_dir.glob("b.*") if p.is_dir()]
    case_dirs.sort(key=lambda p: int(p.name.split(".", 1)[1]) if p.name.split(".", 1)[1].isdigit() else 10**9)
    for case_dir in case_dirs:
        for name in ("case.json", "request.txt", "response.txt", "analysis.json", "analysis_raw.txt"):
            path = case_dir / name
            if path.exists():
                files.append(path)
    return files


def calc_signature(result_dir: Path) -> Dict[str, str | int]:
    hasher = hashlib.sha256()
    file_count = 0

    if not result_dir.exists():
        hasher.update(b"RESULT_DIR_MISSING")
        return {"signature": hasher.hexdigest(), "file_count": 0}

    for path in collect_watch_files(result_dir):
        try:
            st = path.stat()
            rel = path.relative_to(result_dir).as_posix()
            hasher.update(f"{rel}|{st.st_mtime_ns}|{st.st_size}\n".encode("utf-8"))
            file_count += 1
        except Exception:
            continue

    return {"signature": hasher.hexdigest(), "file_count": file_count}


def run_sync(
    result_dir: Path,
    backend: str,
    db_path: Path,
    mysql_config: MySQLConfig,
    log_file: Path,
    state_file: Path,
    state: Dict,
) -> Dict[str, str | int]:
    stats = sync_result_to_db(
        result_dir=result_dir,
        backend=backend,
        db_path=db_path,
        mysql_config=mysql_config,
    )
    state["last_synced_at"] = now_iso()
    state["last_error"] = ""
    state["last_error_at"] = ""
    state["last_stats"] = stats
    write_state(state_file, state)
    log(
        "sync done "
        + f"backend={stats['backend']} "
        + f"cases={stats['cases_scanned']} "
        + f"req={stats['requests_rows']} "
        + f"rsp={stats['responses_rows']} "
        + f"ana={stats['analyses_rows']}",
        log_file,
    )
    return stats


def main() -> None:
    script_dir = Path(__file__).resolve().parent
    project_root = script_dir.parent

    parser = argparse.ArgumentParser(description="Watch result/b.* and sync into database")
    parser.add_argument("--result-dir", default="result", help="result root directory")
    parser.add_argument("--backend", choices=["sqlite", "mysql"], default="mysql", help="database backend")
    parser.add_argument("--db-path", default="result/result_cases.db", help="sqlite db path")

    parser.add_argument("--mysql-host", default="127.0.0.1", help="MySQL host")
    parser.add_argument("--mysql-port", type=int, default=3306, help="MySQL port")
    parser.add_argument("--mysql-user", default="root", help="MySQL user")
    parser.add_argument("--mysql-password", default="123456", help="MySQL password")
    parser.add_argument("--mysql-database", default="traffic_pipeline", help="MySQL database")

    parser.add_argument("--state-file", default="output/result_db_daemon_state.json", help="state json path")
    parser.add_argument("--log-file", default="output/result_db_daemon.log", help="daemon log path")
    parser.add_argument("--poll-seconds", type=int, default=5, help="poll interval seconds")
    parser.add_argument("--once", action="store_true", help="sync once and exit")
    args = parser.parse_args()

    result_dir = (project_root / args.result_dir).resolve()
    db_path = (project_root / args.db_path).resolve()
    state_file = (project_root / args.state_file).resolve()
    log_file = (project_root / args.log_file).resolve()

    mysql_config = MySQLConfig(
        host=args.mysql_host,
        port=args.mysql_port,
        user=args.mysql_user,
        password=args.mysql_password,
        database=args.mysql_database,
    )

    result_dir.mkdir(parents=True, exist_ok=True)
    if args.backend == "sqlite":
        db_path.parent.mkdir(parents=True, exist_ok=True)

    state = read_state(state_file)
    state["project_root"] = str(project_root)
    state["result_dir"] = str(result_dir)
    state["backend"] = args.backend
    if args.backend == "sqlite":
        state["db_target"] = str(db_path)
    else:
        state["db_target"] = f"mysql://{args.mysql_user}@{args.mysql_host}:{args.mysql_port}/{args.mysql_database}"
    write_state(state_file, state)

    log(f"result db daemon started result_dir={result_dir}", log_file)
    log(f"backend={args.backend} target={state['db_target']}", log_file)

    sig_obj = calc_signature(result_dir)
    state["last_signature"] = sig_obj["signature"]
    state["last_file_count"] = sig_obj["file_count"]
    write_state(state_file, state)

    try:
        run_sync(result_dir, args.backend, db_path, mysql_config, log_file, state_file, state)
    except Exception as exc:  # noqa: BLE001
        state["last_error"] = str(exc)
        state["last_error_at"] = now_iso()
        write_state(state_file, state)
        log(f"sync failed: {exc}", log_file)
        if args.once:
            return

    if args.once:
        log("once done", log_file)
        return

    while True:
        time.sleep(max(args.poll_seconds, 1))
        sig_obj = calc_signature(result_dir)
        current_sig = str(sig_obj["signature"])
        if current_sig == str(state.get("last_signature", "")):
            continue

        state["last_signature"] = current_sig
        state["last_file_count"] = int(sig_obj["file_count"])
        write_state(state_file, state)
        log(f"change detected files={sig_obj['file_count']}", log_file)

        try:
            run_sync(result_dir, args.backend, db_path, mysql_config, log_file, state_file, state)
        except Exception as exc:  # noqa: BLE001
            state["last_error"] = str(exc)
            state["last_error_at"] = now_iso()
            write_state(state_file, state)
            log(f"sync failed: {exc}", log_file)


if __name__ == "__main__":
    main()
