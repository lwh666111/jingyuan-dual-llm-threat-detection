"""Best-effort Windows events used to wake pipeline stages without busy polling."""

from __future__ import annotations

import os
import time
import atexit
import ctypes
import threading
import json
from pathlib import Path
from typing import Any


DETECTION_READY_EVENT = "Local\\JingyuanTrafficPipeline.DetectionReady"
DB_READY_EVENT = "Local\\JingyuanTrafficPipeline.DatabaseReady"
LLM_READY_EVENT = "Local\\JingyuanTrafficPipeline.LlmReady"
INPUT_QUEUE_NAME = "input_ready.jsonl"

_handles: dict[str, int] = {}
_handles_lock = threading.Lock()


def _kernel32():
    kernel32 = ctypes.windll.kernel32
    kernel32.CreateEventW.argtypes = [
        ctypes.c_void_p,
        ctypes.c_bool,
        ctypes.c_bool,
        ctypes.c_wchar_p,
    ]
    kernel32.CreateEventW.restype = ctypes.c_void_p
    kernel32.SetEvent.argtypes = [ctypes.c_void_p]
    kernel32.SetEvent.restype = ctypes.c_bool
    kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    kernel32.WaitForSingleObject.restype = ctypes.c_uint32
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_bool
    return kernel32


def _event_handle(name: str) -> int:
    with _handles_lock:
        handle = _handles.get(name)
        if handle:
            return handle
        handle = int(_kernel32().CreateEventW(None, False, False, name) or 0)
        if handle:
            _handles[name] = handle
        return handle


def _close_handles() -> None:
    if os.name != "nt":
        return
    kernel32 = _kernel32()
    with _handles_lock:
        for handle in _handles.values():
            kernel32.CloseHandle(handle)
        _handles.clear()


atexit.register(_close_handles)


def notify_event(name: str) -> bool:
    if os.name != "nt":
        return False
    kernel32 = _kernel32()
    handle = _event_handle(name)
    if not handle:
        return False
    return bool(kernel32.SetEvent(handle))


def wait_event(name: str, timeout_seconds: float) -> bool:
    timeout_seconds = max(0.0, float(timeout_seconds))
    if os.name != "nt":
        time.sleep(timeout_seconds)
        return False
    kernel32 = _kernel32()
    handle = _event_handle(name)
    if not handle:
        time.sleep(timeout_seconds)
        return False
    timeout_ms = min(0xFFFFFFFE, int(timeout_seconds * 1000))
    return kernel32.WaitForSingleObject(handle, timeout_ms) == 0


def append_input_ready(queue_path: Path, input_path: Path) -> None:
    """Append a durable queue record before waking downstream consumers."""
    queue_path.parent.mkdir(parents=True, exist_ok=True)
    record = json.dumps(
        {"path": str(input_path.resolve()), "queued_at_ns": time.time_ns()},
        ensure_ascii=True,
        separators=(",", ":"),
    )
    with queue_path.open("a", encoding="ascii", newline="\n") as handle:
        handle.write(record + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def read_input_ready(queue_path: Path, offset: int) -> tuple[list[Path], int]:
    """Read complete queue records from byte offset; incomplete tails retry later."""
    if not queue_path.exists():
        return [], 0
    paths: list[Path] = []
    with queue_path.open("rb") as handle:
        size = handle.seek(0, os.SEEK_END)
        offset = max(0, min(int(offset or 0), size))
        handle.seek(offset)
        while True:
            start = handle.tell()
            raw = handle.readline()
            if not raw:
                break
            if not raw.endswith(b"\n"):
                handle.seek(start)
                break
            try:
                payload: dict[str, Any] = json.loads(raw.decode("ascii"))
                value = str(payload.get("path") or "").strip()
                if value:
                    paths.append(Path(value))
            except Exception:
                continue
        return paths, handle.tell()
