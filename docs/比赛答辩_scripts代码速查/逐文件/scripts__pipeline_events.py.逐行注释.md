# `scripts/pipeline_events.py` 逐行注释

**脚本用途：** 提供轻量事件通知，减少文件轮询造成的流水线等待。

**源码行数：** 128　**函数/类数量：** 7

| 行号 | 中文说明 | 原始源码 |
|---:|---|---|
| L0001 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>"""Best-effort Windows events used to wake pipeline stages without busy polling."""</code> |
| L0002 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0003 | 导入后续逻辑所需的模块、类或函数：&#96;from __future__ import annotations&#96;。 | <code>from __future__ import annotations</code> |
| L0004 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0005 | 导入后续逻辑所需的模块、类或函数：&#96;import os&#96;。 | <code>import os</code> |
| L0006 | 导入后续逻辑所需的模块、类或函数：&#96;import time&#96;。 | <code>import time</code> |
| L0007 | 导入后续逻辑所需的模块、类或函数：&#96;import atexit&#96;。 | <code>import atexit</code> |
| L0008 | 导入后续逻辑所需的模块、类或函数：&#96;import ctypes&#96;。 | <code>import ctypes</code> |
| L0009 | 导入后续逻辑所需的模块、类或函数：&#96;import threading&#96;。 | <code>import threading</code> |
| L0010 | 导入后续逻辑所需的模块、类或函数：&#96;import json&#96;。 | <code>import json</code> |
| L0011 | 导入后续逻辑所需的模块、类或函数：&#96;from pathlib import Path&#96;。 | <code>from pathlib import Path</code> |
| L0012 | 导入后续逻辑所需的模块、类或函数：&#96;from typing import Any&#96;。 | <code>from typing import Any</code> |
| L0013 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0014 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0015 | 计算并保存 &#96;DETECTION_READY_EVENT&#96;（DETECTIONREADY事件），供后续逻辑使用。 | <code>DETECTION_READY_EVENT = "Local\\JingyuanTrafficPipeline.DetectionReady"</code> |
| L0016 | 计算并保存 &#96;DB_READY_EVENT&#96;（数据库READY事件），供后续逻辑使用。 | <code>DB_READY_EVENT = "Local\\JingyuanTrafficPipeline.DatabaseReady"</code> |
| L0017 | 计算并保存 &#96;LLM_READY_EVENT&#96;（LLMREADY事件），供后续逻辑使用。 | <code>LLM_READY_EVENT = "Local\\JingyuanTrafficPipeline.LlmReady"</code> |
| L0018 | 计算并保存 &#96;INPUT_QUEUE_NAME&#96;（INPUTQUEUENAME），供后续逻辑使用。 | <code>INPUT_QUEUE_NAME = "input_ready.jsonl"</code> |
| L0019 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0020 | 计算并保存 &#96;_handles&#96;（handles），供后续逻辑使用。 | <code>_handles: dict[str, int] = {}</code> |
| L0021 | 计算并保存 &#96;_handles_lock&#96;（handleslock），供后续逻辑使用。 | <code>_handles_lock = threading.Lock()</code> |
| L0022 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0023 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0024 | 定义kernel32函数 &#96;_kernel32&#96;，封装可复用业务逻辑。 | <code>def _kernel32():</code> |
| L0025 | 计算并保存 &#96;kernel32&#96;（kernel32），供后续逻辑使用，当前位于函数 _kernel32。 | <code>    kernel32 = ctypes.windll.kernel32</code> |
| L0026 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _kernel32。 | <code>    kernel32.CreateEventW.argtypes = [</code> |
| L0027 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _kernel32。 | <code>        ctypes.c_void_p,</code> |
| L0028 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _kernel32。 | <code>        ctypes.c_bool,</code> |
| L0029 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _kernel32。 | <code>        ctypes.c_bool,</code> |
| L0030 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _kernel32。 | <code>        ctypes.c_wchar_p,</code> |
| L0031 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 _kernel32。 | <code>    ]</code> |
| L0032 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _kernel32。 | <code>    kernel32.CreateEventW.restype = ctypes.c_void_p</code> |
| L0033 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _kernel32。 | <code>    kernel32.SetEvent.argtypes = [ctypes.c_void_p]</code> |
| L0034 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _kernel32。 | <code>    kernel32.SetEvent.restype = ctypes.c_bool</code> |
| L0035 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _kernel32。 | <code>    kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]</code> |
| L0036 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _kernel32。 | <code>    kernel32.WaitForSingleObject.restype = ctypes.c_uint32</code> |
| L0037 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _kernel32。 | <code>    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]</code> |
| L0038 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _kernel32。 | <code>    kernel32.CloseHandle.restype = ctypes.c_bool</code> |
| L0039 | 结束当前函数并把结果返回给调用方，当前位于函数 _kernel32。 | <code>    return kernel32</code> |
| L0040 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0041 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0042 | 定义事件handle函数 &#96;_event_handle&#96;，封装可复用业务逻辑。 | <code>def _event_handle(name: str) -&gt; int:</code> |
| L0043 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 _event_handle。 | <code>    with _handles_lock:</code> |
| L0044 | 计算并保存 &#96;handle&#96;（handle），供后续逻辑使用，当前位于函数 _event_handle。 | <code>        handle = _handles.get(name)</code> |
| L0045 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _event_handle。 | <code>        if handle:</code> |
| L0046 | 结束当前函数并把结果返回给调用方，当前位于函数 _event_handle。 | <code>            return handle</code> |
| L0047 | 计算并保存 &#96;handle&#96;（handle），供后续逻辑使用，当前位于函数 _event_handle。 | <code>        handle = int(_kernel32().CreateEventW(None, False, False, name) or 0)</code> |
| L0048 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _event_handle。 | <code>        if handle:</code> |
| L0049 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _event_handle。 | <code>            _handles[name] = handle</code> |
| L0050 | 结束当前函数并把结果返回给调用方，当前位于函数 _event_handle。 | <code>        return handle</code> |
| L0051 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0052 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0053 | 定义closehandles函数 &#96;_close_handles&#96;，封装可复用业务逻辑。 | <code>def _close_handles() -&gt; None:</code> |
| L0054 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _close_handles。 | <code>    if os.name != "nt":</code> |
| L0055 | 结束当前函数并把结果返回给调用方，当前位于函数 _close_handles。 | <code>        return</code> |
| L0056 | 计算并保存 &#96;kernel32&#96;（kernel32），供后续逻辑使用，当前位于函数 _close_handles。 | <code>    kernel32 = _kernel32()</code> |
| L0057 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 _close_handles。 | <code>    with _handles_lock:</code> |
| L0058 | 遍历集合中的数据项并逐项处理，当前位于函数 _close_handles。 | <code>        for handle in _handles.values():</code> |
| L0059 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _close_handles。 | <code>            kernel32.CloseHandle(handle)</code> |
| L0060 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _close_handles。 | <code>        _handles.clear()</code> |
| L0061 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0062 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0063 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>atexit.register(_close_handles)</code> |
| L0064 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0065 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0066 | 定义notify事件函数 &#96;notify_event&#96;，封装可复用业务逻辑。 | <code>def notify_event(name: str) -&gt; bool:</code> |
| L0067 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 notify_event。 | <code>    if os.name != "nt":</code> |
| L0068 | 结束当前函数并把结果返回给调用方，当前位于函数 notify_event。 | <code>        return False</code> |
| L0069 | 计算并保存 &#96;kernel32&#96;（kernel32），供后续逻辑使用，当前位于函数 notify_event。 | <code>    kernel32 = _kernel32()</code> |
| L0070 | 计算并保存 &#96;handle&#96;（handle），供后续逻辑使用，当前位于函数 notify_event。 | <code>    handle = _event_handle(name)</code> |
| L0071 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 notify_event。 | <code>    if not handle:</code> |
| L0072 | 结束当前函数并把结果返回给调用方，当前位于函数 notify_event。 | <code>        return False</code> |
| L0073 | 结束当前函数并把结果返回给调用方，当前位于函数 notify_event。 | <code>    return bool(kernel32.SetEvent(handle))</code> |
| L0074 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0075 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0076 | 定义wait事件函数 &#96;wait_event&#96;，封装可复用业务逻辑。 | <code>def wait_event(name: str, timeout_seconds: float) -&gt; bool:</code> |
| L0077 | 计算并保存 &#96;timeout_seconds&#96;（timeoutseconds），供后续逻辑使用，当前位于函数 wait_event。 | <code>    timeout_seconds = max(0.0, float(timeout_seconds))</code> |
| L0078 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 wait_event。 | <code>    if os.name != "nt":</code> |
| L0079 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 wait_event。 | <code>        time.sleep(timeout_seconds)</code> |
| L0080 | 结束当前函数并把结果返回给调用方，当前位于函数 wait_event。 | <code>        return False</code> |
| L0081 | 计算并保存 &#96;kernel32&#96;（kernel32），供后续逻辑使用，当前位于函数 wait_event。 | <code>    kernel32 = _kernel32()</code> |
| L0082 | 计算并保存 &#96;handle&#96;（handle），供后续逻辑使用，当前位于函数 wait_event。 | <code>    handle = _event_handle(name)</code> |
| L0083 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 wait_event。 | <code>    if not handle:</code> |
| L0084 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 wait_event。 | <code>        time.sleep(timeout_seconds)</code> |
| L0085 | 结束当前函数并把结果返回给调用方，当前位于函数 wait_event。 | <code>        return False</code> |
| L0086 | 计算并保存 &#96;timeout_ms&#96;（timeoutms），供后续逻辑使用，当前位于函数 wait_event。 | <code>    timeout_ms = min(0xFFFFFFFE, int(timeout_seconds * 1000))</code> |
| L0087 | 结束当前函数并把结果返回给调用方，当前位于函数 wait_event。 | <code>    return kernel32.WaitForSingleObject(handle, timeout_ms) == 0</code> |
| L0088 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0089 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0090 | 定义appendinputready函数 &#96;append_input_ready&#96;，封装可复用业务逻辑。 | <code>def append_input_ready(queue_path: Path, input_path: Path) -&gt; None:</code> |
| L0091 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 append_input_ready。 | <code>    """Append a durable queue record before waking downstream consumers."""</code> |
| L0092 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 append_input_ready。 | <code>    queue_path.parent.mkdir(parents=True, exist_ok=True)</code> |
| L0093 | 计算并保存 &#96;record&#96;（record），供后续逻辑使用，当前位于函数 append_input_ready。 | <code>    record = json.dumps(</code> |
| L0094 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 append_input_ready。 | <code>        {"path": str(input_path.resolve()), "queued_at_ns": time.time_ns()},</code> |
| L0095 | 计算并保存 &#96;ensure_ascii&#96;（ensureascii），供后续逻辑使用，当前位于函数 append_input_ready。 | <code>        ensure_ascii=True,</code> |
| L0096 | 计算并保存 &#96;separators&#96;（separators），供后续逻辑使用，当前位于函数 append_input_ready。 | <code>        separators=(",", ":"),</code> |
| L0097 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 append_input_ready。 | <code>    )</code> |
| L0098 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 append_input_ready。 | <code>    with queue_path.open("a", encoding="ascii", newline="\n") as handle:</code> |
| L0099 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 append_input_ready。 | <code>        handle.write(record + "\n")</code> |
| L0100 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 append_input_ready。 | <code>        handle.flush()</code> |
| L0101 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 append_input_ready。 | <code>        os.fsync(handle.fileno())</code> |
| L0102 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0103 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0104 | 定义读取inputready函数 &#96;read_input_ready&#96;，封装可复用业务逻辑。 | <code>def read_input_ready(queue_path: Path, offset: int) -&gt; tuple[list[Path], int]:</code> |
| L0105 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 read_input_ready。 | <code>    """Read complete queue records from byte offset; incomplete tails retry later."""</code> |
| L0106 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 read_input_ready。 | <code>    if not queue_path.exists():</code> |
| L0107 | 结束当前函数并把结果返回给调用方，当前位于函数 read_input_ready。 | <code>        return [], 0</code> |
| L0108 | 计算并保存 &#96;paths&#96;（paths），供后续逻辑使用，当前位于函数 read_input_ready。 | <code>    paths: list[Path] = []</code> |
| L0109 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 read_input_ready。 | <code>    with queue_path.open("rb") as handle:</code> |
| L0110 | 计算并保存 &#96;size&#96;（size），供后续逻辑使用，当前位于函数 read_input_ready。 | <code>        size = handle.seek(0, os.SEEK_END)</code> |
| L0111 | 计算并保存 &#96;offset&#96;（offset），供后续逻辑使用，当前位于函数 read_input_ready。 | <code>        offset = max(0, min(int(offset or 0), size))</code> |
| L0112 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 read_input_ready。 | <code>        handle.seek(offset)</code> |
| L0113 | 在条件成立期间循环执行，常用于守护进程轮询，当前位于函数 read_input_ready。 | <code>        while True:</code> |
| L0114 | 计算并保存 &#96;start&#96;（启动），供后续逻辑使用，当前位于函数 read_input_ready。 | <code>            start = handle.tell()</code> |
| L0115 | 计算并保存 &#96;raw&#96;（raw），供后续逻辑使用，当前位于函数 read_input_ready。 | <code>            raw = handle.readline()</code> |
| L0116 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 read_input_ready。 | <code>            if not raw:</code> |
| L0117 | 控制当前循环或占位分支的执行流程，当前位于函数 read_input_ready。 | <code>                break</code> |
| L0118 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 read_input_ready。 | <code>            if not raw.endswith(b"\n"):</code> |
| L0119 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 read_input_ready。 | <code>                handle.seek(start)</code> |
| L0120 | 控制当前循环或占位分支的执行流程，当前位于函数 read_input_ready。 | <code>                break</code> |
| L0121 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 read_input_ready。 | <code>            try:</code> |
| L0122 | 计算并保存 &#96;payload&#96;（payload），供后续逻辑使用，当前位于函数 read_input_ready。 | <code>                payload: dict[str, Any] = json.loads(raw.decode("ascii"))</code> |
| L0123 | 计算并保存 &#96;value&#96;（value），供后续逻辑使用，当前位于函数 read_input_ready。 | <code>                value = str(payload.get("path") or "").strip()</code> |
| L0124 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 read_input_ready。 | <code>                if value:</code> |
| L0125 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 read_input_ready。 | <code>                    paths.append(Path(value))</code> |
| L0126 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 read_input_ready。 | <code>            except Exception:</code> |
| L0127 | 控制当前循环或占位分支的执行流程，当前位于函数 read_input_ready。 | <code>                continue</code> |
| L0128 | 结束当前函数并把结果返回给调用方，当前位于函数 read_input_ready。 | <code>        return paths, handle.tell()</code> |
