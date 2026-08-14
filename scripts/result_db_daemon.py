import argparse
import hashlib
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set

from build_result_db import MySQLConfig, sync_result_to_db
from sync_detection_v2_db import ensure_mysql as ensure_v2_mysql
from sync_detection_v2_db import iter_case_dirs as iter_v2_case_dirs
from sync_detection_v2_db import mysql_connect as v2_mysql_connect
from sync_detection_v2_db import sync_case_mysql as sync_v2_case_mysql
from pipeline_events import DB_READY_EVENT, INPUT_QUEUE_NAME, LLM_READY_EVENT, notify_event, read_input_ready, wait_event


_MYSQL_SCHEMA_READY = False


def iter_raw_input_files(input_dir: Path) -> List[Path]:
    def sequence(path: Path) -> int:
        try:
            return int(path.stem.split(".")[-1])
        except Exception:
            return 10**9

    return [path for path in sorted(input_dir.glob("1.1.*.txt"), key=sequence) if path.is_file()]


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
    # Stream compact JSON to a sibling file.  The old indented json.dumps call
    # needed a second, contiguous in-memory copy of the complete watch index and
    # was the final failure point when the host was under memory pressure.
    temp_path = path.with_suffix(path.suffix + ".tmp")
    encoder = json.JSONEncoder(ensure_ascii=False, separators=(",", ":"))
    with temp_path.open("w", encoding="utf-8") as handle:
        for chunk in encoder.iterencode(state):
            handle.write(chunk)
        handle.flush()
    temp_path.replace(path)


def collect_watch_files(result_dir: Path, input_dir: Path | None = None) -> List[Path]:
    files: List[Path] = []
    if input_dir and input_dir.exists():
        files.extend(sorted(input_dir.glob("1.1.*.txt")))

    case_dirs = [p for p in result_dir.glob("b.*") if p.is_dir()]
    case_dirs.sort(key=lambda p: int(p.name.split(".", 1)[1]) if p.name.split(".", 1)[1].isdigit() else 10**9)
    for case_dir in case_dirs:
        for name in ("case.json", "request.txt", "response.txt", "analysis.json", "analysis_raw.txt"):
            path = case_dir / name
            if path.exists():
                files.append(path)
    return files


def calc_signature(result_dir: Path, input_dir: Path | None = None) -> Dict[str, str | int]:
    hasher = hashlib.sha256()
    file_count = 0

    if not result_dir.exists() and (not input_dir or not input_dir.exists()):
        hasher.update(b"WATCH_DIRS_MISSING")
        return {"signature": hasher.hexdigest(), "file_count": 0}

    for path in collect_watch_files(result_dir, input_dir):
        try:
            st = path.stat()
            try:
                rel = path.relative_to(result_dir.parent).as_posix()
            except Exception:
                rel = str(path)
            hasher.update(f"{rel}|{st.st_mtime_ns}|{st.st_size}\n".encode("utf-8"))
            file_count += 1
        except Exception:
            continue

    return {"signature": hasher.hexdigest(), "file_count": file_count}


def collect_watch_index(result_dir: Path, input_dir: Path) -> Dict[str, str]:
    """Return a compact, persistent fingerprint for incremental synchronization."""
    root = result_dir.parent
    index: Dict[str, str] = {}
    for path in collect_watch_files(result_dir, input_dir):
        try:
            stat = path.stat()
            key = path.relative_to(root).as_posix()
            index[key] = f"{stat.st_mtime_ns}:{stat.st_size}"
        except Exception:
            continue
    return index


def changed_work_items(
    previous: Dict[str, str],
    current: Dict[str, str],
    project_root: Path,
) -> tuple[Set[str] | None, List[Path]]:
    changed = {key for key, value in current.items() if previous.get(key) != value}
    case_names: Set[str] = set()
    input_files: List[Path] = []
    for key in sorted(changed):
        parts = Path(key).parts
        if len(parts) >= 2 and parts[0] == "input" and parts[-1].startswith("1.1."):
            input_files.append(project_root / Path(key))
        elif len(parts) >= 3 and parts[0] == "result" and parts[1].startswith("b."):
            case_names.add(parts[1])
        elif key == "result/manifest.jsonl":
            # Legacy state files may still contain this key.  Case directory
            # fingerprints are authoritative; a manifest-only write must not
            # trigger a full scan of every historical result.
            continue
    return case_names, input_files


def run_sync(
    result_dir: Path,
    input_dir: Path,
    backend: str,
    db_path: Path,
    mysql_config: MySQLConfig,
    log_file: Path,
    state_file: Path,
    state: Dict,
    case_names: Set[str] | None = None,
    input_files: List[Path] | None = None,
    raw_engine: object | None = None,
) -> Dict[str, str | int]:
    global _MYSQL_SCHEMA_READY
    sync_started = time.perf_counter()
    # RAW-only changes are the normal hot path. Running the legacy b.* importer
    # here needlessly performs schema checks and full-table counts before every
    # live packet, which can add several seconds on the Windows server.
    if case_names is not None and not case_names:
        stats = {
            "backend": backend,
            "target": (
                str(db_path)
                if backend == "sqlite"
                else f"mysql://{mysql_config.user}@{mysql_config.host}:{mysql_config.port}/{mysql_config.database}"
            ),
            "cases_scanned": 0,
            "cases_with_analysis_json": 0,
            "requests_rows": 0,
            "responses_rows": 0,
            "analyses_rows": 0,
            "demo_event_rows": 0,
        }
    else:
        stats = sync_result_to_db(
            result_dir=result_dir,
            backend=backend,
            db_path=db_path,
            mysql_config=mysql_config,
            case_names=case_names,
        )
    if backend == "mysql":
        try:
            conn = v2_mysql_connect(mysql_config)
            # Schema introspection belongs to startup. Repeating DDL checks for
            # every captured packet added seconds to the live detection path.
            if not _MYSQL_SCHEMA_READY:
                ensure_v2_mysql(conn)
                from raw_llm_review import ensure_review_schema
                from sync_raw_http_logs import ensure_demo_attack_events

                ensure_review_schema(conn)
                ensure_demo_attack_events(conn)
                _MYSQL_SCHEMA_READY = True
            raw_totals = {"files": 0, "raw": 0, "candidate": 0, "attack": 0, "model": 0, "poc": 0, "behavior": 0, "errors": 0}
            raw_paths = iter_raw_input_files(input_dir) if input_files is None else input_files
            engine = raw_engine
            if raw_paths and engine is None:
                from security_detection_v2 import DetectionEngineV2

                engine = DetectionEngineV2()
            if raw_paths:
                from sync_raw_http_logs import sync_input_file_mysql
            for input_file in raw_paths:
                for attempt in range(4):
                    try:
                        row_stats = sync_input_file_mysql(conn, input_file, engine)
                        for key in ("files", "raw", "candidate", "attack", "model", "poc", "behavior"):
                            raw_totals[key] += int(row_stats.get(key, 0))
                        break
                    except Exception as exc:  # noqa: BLE001
                        is_deadlock = getattr(exc, "args", [None])[0] in {1205, 1213}
                        try:
                            conn.rollback()
                        except Exception:
                            pass
                        if is_deadlock and attempt < 3:
                            time.sleep(0.08 * (2**attempt))
                            continue
                        raw_totals["errors"] += 1
                        log(f"raw sync failed file={input_file}: {exc}", log_file)
                        break
            v2_totals = {"cases": 0, "raw": 0, "candidate": 0, "attack": 0, "model": 0, "poc": 0, "behavior": 0}
            for case_dir in iter_v2_case_dirs(result_dir):
                if case_names is not None and case_dir.name not in case_names:
                    continue
                row_stats = sync_v2_case_mysql(conn, case_dir)
                if row_stats.get("raw"):
                    v2_totals["cases"] += 1
                for key in ("raw", "candidate", "attack", "model", "poc", "behavior"):
                    v2_totals[key] += int(row_stats.get(key, 0))
            # mysql_connect normally uses autocommit, while tests and future
            # deployments may choose a transactional connection. Keep the
            # publication boundary explicit before waking the LLM daemon.
            conn.commit()
            conn.close()
            stats["v2_layered_rows"] = v2_totals
            stats["raw_input_rows"] = raw_totals
        except Exception as exc:  # noqa: BLE001
            stats["v2_layered_error"] = str(exc)
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
        + f"ana={stats['analyses_rows']} "
        + f"elapsed_ms={int((time.perf_counter() - sync_started) * 1000)} "
        + f"demo={stats.get('demo_event_rows', 0)} "
        + f"raw_input={stats.get('raw_input_rows', {}).get('raw', 0) if isinstance(stats.get('raw_input_rows'), dict) else 0}",
        log_file,
    )
    return stats


def main() -> None:
    script_dir = Path(__file__).resolve().parent
    project_root = script_dir.parent

    parser = argparse.ArgumentParser(description="Watch result/b.* and sync into database")
    parser.add_argument("--result-dir", default="result", help="result root directory")
    parser.add_argument("--input-dir", default="input", help="input raw HTTP txt directory")
    parser.add_argument("--backend", choices=["sqlite", "mysql"], default="mysql", help="database backend")
    parser.add_argument("--db-path", default="result/result_cases.db", help="sqlite db path")

    parser.add_argument("--mysql-host", default="127.0.0.1", help="MySQL host")
    parser.add_argument("--mysql-port", type=int, default=3306, help="MySQL port")
    parser.add_argument("--mysql-user", default="root", help="MySQL user")
    parser.add_argument("--mysql-password", default="123456", help="MySQL password")
    parser.add_argument("--mysql-database", default="traffic_pipeline", help="MySQL database")

    parser.add_argument("--state-file", default="output/result_db_daemon_state.json", help="state json path")
    parser.add_argument("--log-file", default="output/result_db_daemon.log", help="daemon log path")
    parser.add_argument("--poll-seconds", type=int, default=1, help="fallback poll interval seconds")
    parser.add_argument("--once", action="store_true", help="sync once and exit")
    args = parser.parse_args()

    result_dir = (project_root / args.result_dir).resolve()
    input_dir = (project_root / args.input_dir).resolve()
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
    input_dir.mkdir(parents=True, exist_ok=True)
    if args.backend == "sqlite":
        db_path.parent.mkdir(parents=True, exist_ok=True)

    state = read_state(state_file)
    state["project_root"] = str(project_root)
    state["result_dir"] = str(result_dir)
    state["input_dir"] = str(input_dir)
    state["backend"] = args.backend
    if args.backend == "sqlite":
        state["db_target"] = str(db_path)
    else:
        state["db_target"] = f"mysql://{args.mysql_user}@{args.mysql_host}:{args.mysql_port}/{args.mysql_database}"
    write_state(state_file, state)

    log(f"result db daemon started result_dir={result_dir}", log_file)
    log(f"raw input watch dir={input_dir}", log_file)
    log(f"backend={args.backend} target={state['db_target']}", log_file)
    input_queue = project_root / "output" / INPUT_QUEUE_NAME
    reset_request = project_root / "output" / "pipeline_reset.request"
    state.setdefault("input_queue_offset", 0)

    raw_engine: object | None = None
    if args.backend == "mysql":
        # Pay the PyTorch/model initialization cost during service startup, not
        # on the first live request.  The engine remains resident after its
        # first use either way; eager warm-up only moves that latency out of the
        # detection critical path.
        try:
            warm_started = time.perf_counter()
            from security_detection_v2 import DetectionEngineV2

            raw_engine = DetectionEngineV2()
            log(
                f"detection engine ready warmup_seconds={time.perf_counter() - warm_started:.3f}",
                log_file,
            )
        except Exception as exc:  # noqa: BLE001
            # Keep result/database synchronization available.  A later input
            # event retries engine construction and records a precise error.
            log(f"detection engine warmup failed; will retry on input: {exc}", log_file)

    current_index = collect_watch_index(result_dir, input_dir)
    previous_index = state.get("watch_index")
    initial_case_names: Set[str] | None = None
    initial_input_files: List[Path] | None = None
    if isinstance(previous_index, dict):
        initial_case_names, initial_input_files = changed_work_items(previous_index, current_index, project_root)

    if not isinstance(previous_index, dict) or initial_case_names is None or initial_case_names or initial_input_files:
        try:
            if (initial_input_files is None or initial_input_files) and raw_engine is None:
                from security_detection_v2 import DetectionEngineV2

                raw_engine = DetectionEngineV2()
            run_sync(
                result_dir,
                input_dir,
                args.backend,
                db_path,
                mysql_config,
                log_file,
                state_file,
                state,
                case_names=initial_case_names,
                input_files=initial_input_files,
                raw_engine=raw_engine,
            )
            state["watch_index"] = current_index
            state["last_signature"] = calc_signature(result_dir, input_dir)["signature"]
            state["last_file_count"] = len(current_index)
            write_state(state_file, state)
        except Exception as exc:  # noqa: BLE001
            state["last_error"] = str(exc)
            state["last_error_at"] = now_iso()
            write_state(state_file, state)
            log(f"sync failed: {exc}", log_file)
            if args.once:
                return
    else:
        log("no changes since last successful sync", log_file)

    if args.once:
        log("once done", log_file)
        return

    next_fallback_scan_at = time.monotonic() + 30.0
    while True:
        awakened = wait_event(DB_READY_EVENT, max(args.poll_seconds, 1))
        try:
            if reset_request.exists():
                # Emergency reset establishes the current filesystem as the
                # new baseline. Already captured files are preserved, but no
                # stale input/result work is replayed after queue cancellation.
                state["watch_index"] = collect_watch_index(result_dir, input_dir)
                state["input_queue_offset"] = input_queue.stat().st_size if input_queue.exists() else 0
                write_state(state_file, state)
                reset_request.unlink(missing_ok=True)
                log("emergency queue reset applied", log_file)
                continue
            queued_paths, next_queue_offset = read_input_ready(input_queue, int(state.get("input_queue_offset") or 0))
            if queued_paths:
                input_root = input_dir.resolve()
                unique_paths: List[Path] = []
                seen: Set[str] = set()
                for path in queued_paths:
                    resolved = path.resolve()
                    if input_root not in resolved.parents or not resolved.is_file():
                        continue
                    key = str(resolved).lower()
                    if key not in seen:
                        seen.add(key)
                        unique_paths.append(resolved)
                for start in range(0, len(unique_paths), 100):
                    batch = unique_paths[start : start + 100]
                    if not batch:
                        continue
                    log(f"durable queue batch inputs={len(batch)} remaining={max(0, len(unique_paths) - start - len(batch))}", log_file)
                    if raw_engine is None:
                        from security_detection_v2 import DetectionEngineV2

                        raw_engine = DetectionEngineV2()
                    batch_stats = run_sync(
                        result_dir, input_dir, args.backend, db_path, mysql_config,
                        log_file, state_file, state, case_names=set(),
                        input_files=batch, raw_engine=raw_engine,
                    )
                    raw_stats = batch_stats.get("raw_input_rows")
                    if not isinstance(raw_stats, dict):
                        raise RuntimeError(
                            f"durable queue batch was not committed: {batch_stats.get('v2_layered_error', 'missing raw stats')}"
                        )
                    if int(raw_stats.get("errors") or 0) > 0:
                        raise RuntimeError(
                            f"durable queue batch has {raw_stats.get('errors')} failed input file(s); cursor retained for retry"
                        )
                    notify_event(LLM_READY_EVENT)
                state["input_queue_offset"] = next_queue_offset
                write_state(state_file, state)
                continue

            # Queue delivery is the live path. A low-frequency directory scan
            # only recovers writes from legacy tools or a damaged event queue.
            if not awakened and time.monotonic() < next_fallback_scan_at:
                continue
            next_fallback_scan_at = time.monotonic() + 30.0

            current_index = collect_watch_index(result_dir, input_dir)
            previous_index = state.get("watch_index")
            if isinstance(previous_index, dict) and current_index == previous_index:
                continue

            if isinstance(previous_index, dict):
                case_names, input_files = changed_work_items(previous_index, current_index, project_root)
            else:
                case_names, input_files = None, None
            changed_cases = "all" if case_names is None else str(len(case_names))
            changed_inputs = "all" if input_files is None else str(len(input_files))
            log(
                f"change detected files={len(current_index)} cases={changed_cases} inputs={changed_inputs}",
                log_file,
            )
            if (input_files is None or input_files) and raw_engine is None:
                from security_detection_v2 import DetectionEngineV2

                raw_engine = DetectionEngineV2()
            run_sync(
                result_dir,
                input_dir,
                args.backend,
                db_path,
                mysql_config,
                log_file,
                state_file,
                state,
                case_names=case_names,
                input_files=input_files,
                raw_engine=raw_engine,
            )
            if input_files is None or input_files:
                notify_event(LLM_READY_EVENT)
            state["watch_index"] = current_index
            state["last_signature"] = calc_signature(result_dir, input_dir)["signature"]
            state["last_file_count"] = len(current_index)
            write_state(state_file, state)
            if awakened:
                log("input event processed without waiting for fallback poll", log_file)
        except Exception as exc:  # noqa: BLE001
            state["last_error"] = str(exc)
            state["last_error_at"] = now_iso()
            try:
                write_state(state_file, state)
            except Exception as state_exc:  # noqa: BLE001
                # Keep the daemon alive even when the host temporarily cannot
                # allocate enough memory or disk space for diagnostic state.
                log(f"state write skipped after sync failure: {state_exc}", log_file)
            log(f"sync failed and will retry: {exc}", log_file)


if __name__ == "__main__":
    main()
