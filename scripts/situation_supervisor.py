from __future__ import annotations

import argparse
import socket
import subprocess
import sys
import time
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import pymysql
from pymysql.cursors import DictCursor


def log(message: str) -> None:
    print(f"[{datetime.now().isoformat(timespec='seconds')}] {message}", flush=True)


def validated_int_text(value: object, fallback: int, minimum: int, maximum: int) -> str:
    try:
        parsed = int(str(value).strip())
    except (TypeError, ValueError):
        parsed = int(fallback)
    if parsed < minimum or parsed > maximum:
        parsed = int(fallback)
    return str(parsed)


def resolve_tshark_interface_index(configured: str) -> str:
    value = str(configured or "").strip()
    if not value or value.isdigit() or value.lower() in {"auto", "none", "off"}:
        return value
    try:
        result = subprocess.run(
            ["tshark", "-D"], capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=12,
        )
        if result.returncode == 0:
            needle = value.lower()
            for line in result.stdout.splitlines():
                match = re.match(r"^\s*(\d+)\.\s+(.+)$", line)
                if match and needle in match.group(2).lower():
                    return match.group(1)
    except Exception:
        pass
    return value


def stop(proc: Optional[subprocess.Popen], name: str) -> None:
    if not proc or proc.poll() is not None:
        return
    log(f"stopping {name} pid={proc.pid}")
    proc.terminate()
    try:
        proc.wait(timeout=8)
    except subprocess.TimeoutExpired:
        proc.kill()


def load_runtime_config(args: argparse.Namespace) -> Dict[str, str]:
    fallback = {
        "capture_interface": args.interface,
        "llm_model": args.model,
        "situation_minimum_actions": str(args.minimum_actions),
        "situation_window_minutes": str(args.window_minutes),
        "situation_inactivity_minutes": str(args.inactivity_minutes),
        "scan_port_threshold": str(args.scan_port_threshold),
        "scan_window_seconds": str(args.scan_window_seconds),
    }
    try:
        conn = pymysql.connect(
            host=args.mysql_host,
            port=args.mysql_port,
            user=args.mysql_user,
            password=args.mysql_password,
            database=args.mysql_database,
            charset="utf8mb4",
            cursorclass=DictCursor,
            connect_timeout=3,
        )
        with conn.cursor() as cur:
            cur.execute(
                """SELECT config_key,config_value FROM demo_system_config
                   WHERE config_key IN (
                     'capture_interface','capture_interface_identity','llm_model','situation_minimum_actions',
                     'situation_window_minutes','situation_inactivity_minutes',
                     'scan_port_threshold','scan_window_seconds'
                   )"""
            )
            rows = cur.fetchall()
        conn.close()
        for row in rows:
            fallback[str(row["config_key"])] = str(row["config_value"] or "").strip()
    except Exception as exc:
        log(f"runtime config fallback: {exc}")
    fallback["situation_minimum_actions"] = validated_int_text(
        fallback.get("situation_minimum_actions"), args.minimum_actions, 3, 12
    )
    fallback["situation_window_minutes"] = validated_int_text(
        fallback.get("situation_window_minutes"), args.window_minutes, 1, 1440
    )
    fallback["situation_inactivity_minutes"] = validated_int_text(
        fallback.get("situation_inactivity_minutes"), args.inactivity_minutes, 1, 1440
    )
    fallback["scan_port_threshold"] = validated_int_text(
        fallback.get("scan_port_threshold"), args.scan_port_threshold, 3, 65535
    )
    fallback["scan_window_seconds"] = validated_int_text(
        fallback.get("scan_window_seconds"), args.scan_window_seconds, 10, 3600
    )
    fallback["capture_interface"] = (
        fallback.get("capture_interface_identity") or fallback.get("capture_interface") or args.interface
    )
    fallback["capture_interface"] = resolve_tshark_interface_index(fallback["capture_interface"])
    return fallback


def common_mysql_args(args: argparse.Namespace) -> List[str]:
    return [
        "--mysql-host", args.mysql_host,
        "--mysql-port", str(args.mysql_port),
        "--mysql-user", args.mysql_user,
        "--mysql-password", args.mysql_password,
        "--mysql-database", args.mysql_database,
    ]


def situation_command(args: argparse.Namespace, runtime: Optional[Dict[str, str]] = None) -> List[str]:
    runtime = runtime or {}
    return [
        args.python_exe,
        str(args.scripts_dir / "situation_daemon.py"),
        *common_mysql_args(args),
        "--target-asset", args.target_asset,
        "--minimum-actions", runtime.get("situation_minimum_actions", str(args.minimum_actions)),
        "--window-minutes", runtime.get("situation_window_minutes", str(args.window_minutes)),
        "--inactivity-minutes", runtime.get("situation_inactivity_minutes", str(args.inactivity_minutes)),
        "--lookback-days", str(args.lookback_days),
        "--poll-seconds", str(args.poll_seconds),
    ]


def ai_command(args: argparse.Namespace, model: str) -> List[str]:
    return [
        args.python_exe,
        str(args.scripts_dir / "situation_ai_daemon.py"),
        *common_mysql_args(args),
        "--ollama-url", args.ollama_url,
        "--model", model,
        "--rag-db-path", args.rag_db_path,
        "--rag-data-dir", args.rag_data_dir,
        "--rag-api-config", args.rag_api_config,
        "--poll-seconds", str(args.poll_seconds),
        "--heartbeat-file", str(getattr(args, "ai_heartbeat_file", Path("output/situation_ai_heartbeat.json"))),
    ]


def sensor_command(args: argparse.Namespace, interface: str, runtime: Optional[Dict[str, str]] = None) -> List[str]:
    runtime = runtime or {}
    return [
        args.python_exe,
        str(args.scripts_dir / "port_scan_sensor.py"),
        *common_mysql_args(args),
        "--interface", interface,
        "--target-asset", args.target_asset,
        "--unique-port-threshold", runtime.get("scan_port_threshold", str(args.scan_port_threshold)),
        "--window-seconds", runtime.get("scan_window_seconds", str(args.scan_window_seconds)),
    ]


def neo4j_command(args: argparse.Namespace) -> List[str]:
    return [
        args.python_exe,
        str(args.scripts_dir / "situation_neo4j_sync.py"),
        *common_mysql_args(args),
        "--neo4j-url", args.neo4j_url,
        "--neo4j-user", args.neo4j_user,
        "--neo4j-password", args.neo4j_password,
        "--neo4j-database", args.neo4j_database,
        "--poll-seconds", str(args.poll_seconds),
    ]


def auto_defense_command(args: argparse.Namespace) -> List[str]:
    return [
        args.python_exe,
        str(args.scripts_dir / "auto_defense_daemon.py"),
        *common_mysql_args(args),
        "--poll-seconds", "2",
        "--log-file", "output/auto_defense_daemon.log",
    ]


def start(command: List[str], name: str, cwd: Path) -> subprocess.Popen:
    proc = subprocess.Popen(command, cwd=str(cwd), text=True, encoding="utf-8", errors="replace")
    log(f"started {name} pid={proc.pid}")
    return proc


def main() -> None:
    parser = argparse.ArgumentParser(description="Self-healing situation correlation, AI and scan supervisor")
    parser.add_argument("--python-exe", default=sys.executable)
    parser.add_argument("--scripts-dir", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--mysql-host", default="127.0.0.1")
    parser.add_argument("--mysql-port", type=int, default=3306)
    parser.add_argument("--mysql-user", default="root")
    parser.add_argument("--mysql-password", default="123456")
    parser.add_argument("--mysql-database", default="traffic_pipeline")
    parser.add_argument("--interface", default="")
    parser.add_argument("--model", default="qwen2.5:3b")
    parser.add_argument("--ollama-url", default="http://127.0.0.1:11434")
    parser.add_argument("--rag-db-path", default="llm/rag/rag_knowledge.db")
    parser.add_argument("--rag-data-dir", default="D:/JingyuanTrafficPipelineData/rag")
    parser.add_argument("--rag-api-config", default="config/ai_api.local.json")
    parser.add_argument("--target-asset", default=socket.gethostname())
    parser.add_argument("--minimum-actions", type=int, default=3)
    parser.add_argument("--window-minutes", type=int, default=30)
    parser.add_argument("--inactivity-minutes", type=int, default=15)
    parser.add_argument("--lookback-days", type=int, default=30)
    parser.add_argument("--poll-seconds", type=int, default=10)
    parser.add_argument("--ai-heartbeat-file", type=Path, default=Path("output/situation_ai_heartbeat.json"))
    parser.add_argument("--ai-heartbeat-timeout", type=int, default=210)
    parser.add_argument("--scan-port-threshold", type=int, default=10)
    parser.add_argument("--scan-window-seconds", type=int, default=60)
    parser.add_argument("--neo4j-url", default="")
    parser.add_argument("--neo4j-user", default="neo4j")
    parser.add_argument("--neo4j-password", default="")
    parser.add_argument("--neo4j-database", default="neo4j")
    args = parser.parse_args()
    args.scripts_dir = args.scripts_dir.resolve()
    project_root = args.scripts_dir.parent
    if not args.ai_heartbeat_file.is_absolute():
        args.ai_heartbeat_file = project_root / args.ai_heartbeat_file

    processes: Dict[str, Optional[subprocess.Popen]] = {
        "correlator": None,
        "ai": None,
        "sensor": None,
        "neo4j": None,
        "auto-defense": None,
    }
    active_model = ""
    active_interface = ""
    active_correlation_config: tuple[str, str, str] = ("", "", "")
    active_scan_config: tuple[str, str] = ("", "")
    runtime_config: Dict[str, str] = {}
    next_config_check = 0.0
    try:
        while True:
            if time.monotonic() >= next_config_check:
                config = load_runtime_config(args)
                model = config.get("llm_model") or args.model
                interface = config.get("capture_interface") or args.interface
                correlation_config = (
                    config.get("situation_minimum_actions", str(args.minimum_actions)),
                    config.get("situation_window_minutes", str(args.window_minutes)),
                    config.get("situation_inactivity_minutes", str(args.inactivity_minutes)),
                )
                scan_config = (
                    config.get("scan_port_threshold", str(args.scan_port_threshold)),
                    config.get("scan_window_seconds", str(args.scan_window_seconds)),
                )
                if model != active_model:
                    stop(processes["ai"], "ai")
                    processes["ai"] = None
                    active_model = model
                if interface != active_interface:
                    stop(processes["sensor"], "sensor")
                    processes["sensor"] = None
                    active_interface = interface
                if correlation_config != active_correlation_config:
                    stop(processes["correlator"], "correlator")
                    processes["correlator"] = None
                    active_correlation_config = correlation_config
                if scan_config != active_scan_config:
                    stop(processes["sensor"], "sensor")
                    processes["sensor"] = None
                    active_scan_config = scan_config
                runtime_config = config
                next_config_check = time.monotonic() + 10

            if processes["correlator"] is None or processes["correlator"].poll() is not None:
                processes["correlator"] = start(situation_command(args, runtime_config), "correlator", project_root)
            if processes["ai"] is None or processes["ai"].poll() is not None:
                processes["ai"] = start(ai_command(args, active_model or args.model), "ai", project_root)
            elif args.ai_heartbeat_file.exists():
                try:
                    heartbeat = json.loads(args.ai_heartbeat_file.read_text(encoding="utf-8-sig"))
                    updated = datetime.fromisoformat(str(heartbeat.get("updated_at") or ""))
                    age = (datetime.now() - updated).total_seconds()
                    if age > max(60, args.ai_heartbeat_timeout):
                        log(f"ai business heartbeat stale ({age:.0f}s), restarting")
                        stop(processes["ai"], "ai")
                        processes["ai"] = None
                except Exception as exc:
                    log(f"ai heartbeat check skipped: {exc}")
            if active_interface and active_interface.lower() not in {"auto", "none", "off"}:
                if processes["sensor"] is None or processes["sensor"].poll() is not None:
                    processes["sensor"] = start(sensor_command(args, active_interface, runtime_config), "sensor", project_root)
            if args.neo4j_url and args.neo4j_password:
                if processes["neo4j"] is None or processes["neo4j"].poll() is not None:
                    processes["neo4j"] = start(neo4j_command(args), "neo4j", project_root)
            if processes["auto-defense"] is None or processes["auto-defense"].poll() is not None:
                processes["auto-defense"] = start(auto_defense_command(args), "auto-defense", project_root)
            time.sleep(3)
    except KeyboardInterrupt:
        log("shutdown requested")
    finally:
        for name, proc in processes.items():
            stop(proc, name)


if __name__ == "__main__":
    main()
