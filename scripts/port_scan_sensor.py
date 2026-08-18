from __future__ import annotations

import argparse
import hashlib
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from situation_core import SecurityAction, parse_timestamp
from situation_store import MySQLSettings, MySQLSituationStore


@dataclass
class ScanWindow:
    source_ip: str
    destination_ip: str
    started_at: datetime
    last_seen_at: datetime
    ports: Set[int] = field(default_factory=set)
    packet_count: int = 0


class PortScanDetector:
    def __init__(
        self,
        unique_port_threshold: int = 10,
        window_seconds: int = 60,
        target_asset: str = "local-server",
    ) -> None:
        self.unique_port_threshold = max(3, int(unique_port_threshold))
        self.window = timedelta(seconds=max(10, int(window_seconds)))
        self.target_asset = str(target_asset or "local-server")
        self._windows: Dict[Tuple[str, str, int], ScanWindow] = {}

    def observe(self, occurred_at: datetime, source_ip: str, destination_ip: str, destination_port: int) -> None:
        timestamp = parse_timestamp(occurred_at)
        source = str(source_ip)
        destination = str(destination_ip)
        key = None
        row = None
        # Fixed epoch buckets split scans that cross a minute boundary. Keep a
        # rolling source/target window so contiguous SYNs remain one action.
        candidates = sorted(
            (
                (window_key, window)
                for window_key, window in self._windows.items()
                if window.source_ip == source and window.destination_ip == destination
            ),
            key=lambda item: item[1].last_seen_at,
            reverse=True,
        )
        for window_key, window in candidates:
            earliest = min(window.started_at, timestamp)
            latest = max(window.last_seen_at, timestamp)
            if latest - earliest <= self.window:
                key, row = window_key, window
                break
        if row is None:
            bucket = int(timestamp.timestamp() * 1000)
            key = (source, destination, bucket)
            row = ScanWindow(source, destination, timestamp, timestamp)
            self._windows[key] = row
        row.started_at = min(row.started_at, timestamp)
        row.last_seen_at = max(row.last_seen_at, timestamp)
        row.ports.add(int(destination_port))
        row.packet_count += 1

    def actions(self, now: Optional[datetime] = None, include_active: bool = True) -> List[SecurityAction]:
        now_utc = parse_timestamp(now or datetime.now(timezone.utc))
        result: List[SecurityAction] = []
        for (source_ip, destination_ip, bucket), row in sorted(self._windows.items()):
            if len(row.ports) < self.unique_port_threshold:
                continue
            if not include_active and now_utc - row.last_seen_at <= self.window:
                continue
            digest = hashlib.sha1(f"scan|{source_ip}|{destination_ip}|{bucket}".encode("utf-8")).hexdigest()[:20].upper()
            confidence = min(0.99, 0.58 + len(row.ports) / max(self.unique_port_threshold * 5.0, 50.0))
            result.append(
                SecurityAction(
                    action_id=f"ACT-SCAN-{digest}",
                    source_ip=source_ip,
                    target_asset=self.target_asset,
                    action_type="PORT_SCAN",
                    occurred_at=row.started_at,
                    last_seen_at=row.last_seen_at,
                    protocol="TCP",
                    sensor="tshark_syn_scan",
                    count=row.packet_count,
                    confidence=confidence,
                    severity="high" if len(row.ports) >= self.unique_port_threshold * 3 else "medium",
                    evidence_refs=[f"syn-window:{bucket}"],
                    metadata={
                        "destination_ip": destination_ip,
                        "unique_port_count": len(row.ports),
                        "ports": sorted(row.ports)[:256],
                    },
                )
            )
        return result

    def prune(self, now: Optional[datetime] = None, retention_windows: int = 3) -> None:
        now_utc = parse_timestamp(now or datetime.now(timezone.utc))
        cutoff = now_utc - self.window * max(2, int(retention_windows))
        self._windows = {key: row for key, row in self._windows.items() if row.last_seen_at >= cutoff}


def find_tshark(explicit: str = "") -> str:
    candidates = [explicit, shutil.which("tshark") or "", r"C:\Program Files\Wireshark\tshark.exe"]
    for candidate in candidates:
        if candidate and Path(candidate).exists():
            return str(Path(candidate))
    raise FileNotFoundError("未找到 tshark，请先安装 Wireshark 并启用 Npcap")


def tshark_command(tshark: str, interface: str) -> List[str]:
    return [
        tshark,
        "-l",
        "-n",
        "-i",
        str(interface),
        "-f",
        "tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn",
        "-Y",
        "tcp.flags.syn == 1 && tcp.flags.ack == 0 && ip.src && ip.dst",
        "-T",
        "fields",
        "-E",
        "separator=\\t",
        "-e",
        "frame.time_epoch",
        "-e",
        "ip.src",
        "-e",
        "ip.dst",
        "-e",
        "tcp.dstport",
    ]


def parse_packet_line(line: str) -> Optional[Tuple[datetime, str, str, int]]:
    parts = line.strip().split("\t")
    if len(parts) != 4:
        return None
    try:
        timestamp = datetime.fromtimestamp(float(parts[0]), tz=timezone.utc)
        return timestamp, parts[1].strip(), parts[2].strip(), int(parts[3])
    except (TypeError, ValueError):
        return None


def main() -> None:
    parser = argparse.ArgumentParser(description="Detect TCP SYN port scans and write normalized security actions")
    parser.add_argument("--interface", required=True)
    parser.add_argument("--tshark", default="")
    parser.add_argument("--unique-port-threshold", type=int, default=10)
    parser.add_argument("--window-seconds", type=int, default=60)
    parser.add_argument("--flush-seconds", type=int, default=5)
    parser.add_argument("--target-asset", default=socket.gethostname())
    parser.add_argument("--mysql-host", default="127.0.0.1")
    parser.add_argument("--mysql-port", type=int, default=3306)
    parser.add_argument("--mysql-user", default="root")
    parser.add_argument("--mysql-password", default="123456")
    parser.add_argument("--mysql-database", default="traffic_pipeline")
    args = parser.parse_args()

    tshark = find_tshark(args.tshark)
    command = tshark_command(tshark, args.interface)
    detector = PortScanDetector(args.unique_port_threshold, args.window_seconds, args.target_asset)
    store = MySQLSituationStore(
        MySQLSettings(args.mysql_host, args.mysql_port, args.mysql_user, args.mysql_password, args.mysql_database)
    )
    store.ensure_schema()
    print(f"[{datetime.now().isoformat(timespec='seconds')}] port scan sensor: {' '.join(command)}", flush=True)
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace")
    last_flush = time.monotonic()
    try:
        if process.stdout is None:
            raise RuntimeError("tshark stdout unavailable")
        for line in process.stdout:
            packet = parse_packet_line(line)
            if packet:
                detector.observe(*packet)
            if time.monotonic() - last_flush >= max(1, args.flush_seconds):
                actions = detector.actions()
                if actions:
                    store.upsert_actions(actions)
                detector.prune()
                last_flush = time.monotonic()
        rc = process.wait(timeout=5)
        stderr = process.stderr.read() if process.stderr else ""
        raise RuntimeError(f"tshark exited rc={rc}: {stderr[-1000:]}")
    finally:
        if process.poll() is None:
            process.terminate()
        store.close()


if __name__ == "__main__":
    main()
