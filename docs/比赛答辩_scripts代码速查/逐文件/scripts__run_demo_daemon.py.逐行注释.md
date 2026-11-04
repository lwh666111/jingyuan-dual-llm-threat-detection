# `scripts/run_demo_daemon.py` 逐行注释

**脚本用途：** 监控 input 目录并调度小模型检测工作流。

**源码行数：** 326　**函数/类数量：** 10

| 行号 | 中文说明 | 原始源码 |
|---:|---|---|
| L0001 | 导入后续逻辑所需的模块、类或函数：&#96;import argparse&#96;。 | <code>import argparse</code> |
| L0002 | 导入后续逻辑所需的模块、类或函数：&#96;import json&#96;。 | <code>import json</code> |
| L0003 | 导入后续逻辑所需的模块、类或函数：&#96;import re&#96;。 | <code>import re</code> |
| L0004 | 导入后续逻辑所需的模块、类或函数：&#96;import subprocess&#96;。 | <code>import subprocess</code> |
| L0005 | 导入后续逻辑所需的模块、类或函数：&#96;import sys&#96;。 | <code>import sys</code> |
| L0006 | 导入后续逻辑所需的模块、类或函数：&#96;import time&#96;。 | <code>import time</code> |
| L0007 | 导入后续逻辑所需的模块、类或函数：&#96;from datetime import datetime&#96;。 | <code>from datetime import datetime</code> |
| L0008 | 导入后续逻辑所需的模块、类或函数：&#96;from pathlib import Path&#96;。 | <code>from pathlib import Path</code> |
| L0009 | 导入后续逻辑所需的模块、类或函数：&#96;from typing import Dict, List, Tuple&#96;。 | <code>from typing import Dict, List, Tuple</code> |
| L0010 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0011 | 导入后续逻辑所需的模块、类或函数：&#96;from pipeline_events import DB_READY_EVENT, DETECTION_READY_EVENT, notify_event, wait_event&#96;。 | <code>from pipeline_events import DB_READY_EVENT, DETECTION_READY_EVENT, notify_event, wait_event</code> |
| L0012 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0013 | 计算并保存 &#96;FILE_PATTERN&#96;（FILEPATTERN），供后续逻辑使用。 | <code>FILE_PATTERN = re.compile(r"^1\.1\.(\d+)\.txt$")</code> |
| L0014 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0015 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0016 | 定义nowiso函数 &#96;now_iso&#96;，封装可复用业务逻辑。 | <code>def now_iso() -&gt; str:</code> |
| L0017 | 结束当前函数并把结果返回给调用方，当前位于函数 now_iso。 | <code>    return datetime.now().isoformat(timespec="seconds")</code> |
| L0018 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0019 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0020 | 定义log函数 &#96;log&#96;，封装可复用业务逻辑。 | <code>def log(msg: str, log_file: Path) -&gt; None:</code> |
| L0021 | 计算并保存 &#96;line&#96;（line），供后续逻辑使用，当前位于函数 log。 | <code>    line = f"[{now_iso()}] {msg}"</code> |
| L0022 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 log。 | <code>    print(line, flush=True)</code> |
| L0023 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 log。 | <code>    log_file.parent.mkdir(parents=True, exist_ok=True)</code> |
| L0024 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 log。 | <code>    with log_file.open("a", encoding="utf-8") as f:</code> |
| L0025 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 log。 | <code>        f.write(line + "\n")</code> |
| L0026 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0027 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0028 | 定义加载state函数 &#96;load_state&#96;，封装可复用业务逻辑。 | <code>def load_state(path: Path) -&gt; Dict:</code> |
| L0029 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 load_state。 | <code>    if not path.exists():</code> |
| L0030 | 结束当前函数并把结果返回给调用方，当前位于函数 load_state。 | <code>        return {</code> |
| L0031 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_state。 | <code>            "version": 1,</code> |
| L0032 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_state。 | <code>            "success": {},</code> |
| L0033 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_state。 | <code>            "failed": {},</code> |
| L0034 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_state。 | <code>            "ignored": {},</code> |
| L0035 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 load_state。 | <code>        }</code> |
| L0036 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 load_state。 | <code>    try:</code> |
| L0037 | 计算并保存 &#96;state&#96;（state），供后续逻辑使用，当前位于函数 load_state。 | <code>        state = json.loads(path.read_text(encoding="utf-8"))</code> |
| L0038 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 load_state。 | <code>        if not isinstance(state, dict):</code> |
| L0039 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 load_state。 | <code>            raise ValueError("invalid state object")</code> |
| L0040 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_state。 | <code>        state.setdefault("version", 1)</code> |
| L0041 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_state。 | <code>        state.setdefault("success", {})</code> |
| L0042 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_state。 | <code>        state.setdefault("failed", {})</code> |
| L0043 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_state。 | <code>        state.setdefault("ignored", {})</code> |
| L0044 | 结束当前函数并把结果返回给调用方，当前位于函数 load_state。 | <code>        return state</code> |
| L0045 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 load_state。 | <code>    except Exception:</code> |
| L0046 | 结束当前函数并把结果返回给调用方，当前位于函数 load_state。 | <code>        return {</code> |
| L0047 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_state。 | <code>            "version": 1,</code> |
| L0048 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_state。 | <code>            "success": {},</code> |
| L0049 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_state。 | <code>            "failed": {},</code> |
| L0050 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_state。 | <code>            "ignored": {},</code> |
| L0051 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 load_state。 | <code>        }</code> |
| L0052 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0053 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0054 | 定义保存state函数 &#96;save_state&#96;，封装可复用业务逻辑。 | <code>def save_state(path: Path, state: Dict) -&gt; None:</code> |
| L0055 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 save_state。 | <code>    path.parent.mkdir(parents=True, exist_ok=True)</code> |
| L0056 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 save_state。 | <code>    path.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")</code> |
| L0057 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0058 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0059 | 定义列出inputfiles函数 &#96;list_input_files&#96;，封装可复用业务逻辑。 | <code>def list_input_files(input_dir: Path, file_order: str = "newest") -&gt; List[Tuple[int, Path]]:</code> |
| L0060 | 计算并保存 &#96;items&#96;（数据项），供后续逻辑使用，当前位于函数 list_input_files。 | <code>    items: List[Tuple[int, Path]] = []</code> |
| L0061 | 遍历集合中的数据项并逐项处理，当前位于函数 list_input_files。 | <code>    for p in input_dir.glob("1.1.*.txt"):</code> |
| L0062 | 计算并保存 &#96;m&#96;（m），供后续逻辑使用，当前位于函数 list_input_files。 | <code>        m = FILE_PATTERN.match(p.name)</code> |
| L0063 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 list_input_files。 | <code>        if not m:</code> |
| L0064 | 控制当前循环或占位分支的执行流程，当前位于函数 list_input_files。 | <code>            continue</code> |
| L0065 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 list_input_files。 | <code>        items.append((int(m.group(1)), p))</code> |
| L0066 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_input_files。 | <code>    reverse = str(file_order).lower() == "newest"</code> |
| L0067 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_input_files。 | <code>    items.sort(key=lambda x: x[0], reverse=reverse)</code> |
| L0068 | 结束当前函数并把结果返回给调用方，当前位于函数 list_input_files。 | <code>    return items</code> |
| L0069 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0070 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0071 | 定义isfilestable函数 &#96;is_file_stable&#96;，封装可复用业务逻辑。 | <code>def is_file_stable(path: Path, stable_seconds: int) -&gt; bool:</code> |
| L0072 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 is_file_stable。 | <code>    if not path.exists():</code> |
| L0073 | 结束当前函数并把结果返回给调用方，当前位于函数 is_file_stable。 | <code>        return False</code> |
| L0074 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 is_file_stable。 | <code>    try:</code> |
| L0075 | 计算并保存 &#96;stat&#96;（stat），供后续逻辑使用，当前位于函数 is_file_stable。 | <code>        stat = path.stat()</code> |
| L0076 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 is_file_stable。 | <code>    except OSError:</code> |
| L0077 | 结束当前函数并把结果返回给调用方，当前位于函数 is_file_stable。 | <code>        return False</code> |
| L0078 | 计算并保存 &#96;age&#96;（age），供后续逻辑使用，当前位于函数 is_file_stable。 | <code>    age = time.time() - stat.st_mtime</code> |
| L0079 | 结束当前函数并把结果返回给调用方，当前位于函数 is_file_stable。 | <code>    return age &gt;= stable_seconds and stat.st_size &gt; 0</code> |
| L0080 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0081 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0082 | 定义构建democommand函数 &#96;build_demo_command&#96;，封装可复用业务逻辑。 | <code>def build_demo_command(args, input_path: Path) -&gt; List[str]:</code> |
| L0083 | 计算并保存 &#96;cmd&#96;（cmd），供后续逻辑使用，当前位于函数 build_demo_command。 | <code>    cmd = [</code> |
| L0084 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_demo_command。 | <code>        args.python_exe,</code> |
| L0085 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_demo_command。 | <code>        str(args.demo_script),</code> |
| L0086 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_demo_command。 | <code>        "--input-txt",</code> |
| L0087 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_demo_command。 | <code>        str(input_path),</code> |
| L0088 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_demo_command。 | <code>        "--label-threshold",</code> |
| L0089 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_demo_command。 | <code>        str(args.label_threshold),</code> |
| L0090 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_demo_command。 | <code>        "--top-k",</code> |
| L0091 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_demo_command。 | <code>        str(args.top_k),</code> |
| L0092 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_demo_command。 | <code>        "--export-min-score",</code> |
| L0093 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_demo_command。 | <code>        str(args.export_min_score),</code> |
| L0094 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 build_demo_command。 | <code>    ]</code> |
| L0095 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 build_demo_command。 | <code>    if args.preprocessor:</code> |
| L0096 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 build_demo_command。 | <code>        cmd.extend(["--preprocessor", str(args.preprocessor)])</code> |
| L0097 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 build_demo_command。 | <code>    if args.model:</code> |
| L0098 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 build_demo_command。 | <code>        cmd.extend(["--model", str(args.model)])</code> |
| L0099 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 build_demo_command。 | <code>    if args.update_existing_export:</code> |
| L0100 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 build_demo_command。 | <code>        cmd.append("--update-existing-export")</code> |
| L0101 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 build_demo_command。 | <code>    if args.enable_v2_gate:</code> |
| L0102 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 build_demo_command。 | <code>        cmd.append("--enable-v2-gate")</code> |
| L0103 | 结束当前函数并把结果返回给调用方，当前位于函数 build_demo_command。 | <code>    return cmd</code> |
| L0104 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0105 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0106 | 定义shouldretryfailed函数 &#96;should_retry_failed&#96;，封装可复用业务逻辑。 | <code>def should_retry_failed(failed_info: Dict, retry_cooldown: int) -&gt; bool:</code> |
| L0107 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 should_retry_failed。 | <code>    if not failed_info:</code> |
| L0108 | 结束当前函数并把结果返回给调用方，当前位于函数 should_retry_failed。 | <code>        return True</code> |
| L0109 | 计算并保存 &#96;last_failed_at&#96;（lastfailedat），供后续逻辑使用，当前位于函数 should_retry_failed。 | <code>    last_failed_at = failed_info.get("last_failed_at")</code> |
| L0110 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 should_retry_failed。 | <code>    if not last_failed_at:</code> |
| L0111 | 结束当前函数并把结果返回给调用方，当前位于函数 should_retry_failed。 | <code>        return True</code> |
| L0112 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 should_retry_failed。 | <code>    try:</code> |
| L0113 | 计算并保存 &#96;last_ts&#96;（lastts），供后续逻辑使用，当前位于函数 should_retry_failed。 | <code>        last_ts = datetime.fromisoformat(last_failed_at).timestamp()</code> |
| L0114 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 should_retry_failed。 | <code>    except Exception:</code> |
| L0115 | 结束当前函数并把结果返回给调用方，当前位于函数 should_retry_failed。 | <code>        return True</code> |
| L0116 | 结束当前函数并把结果返回给调用方，当前位于函数 should_retry_failed。 | <code>    return (time.time() - last_ts) &gt;= retry_cooldown</code> |
| L0117 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0118 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0119 | 定义processone函数 &#96;process_one&#96;，封装可复用业务逻辑。 | <code>def process_one(args, state: Dict, path: Path, idx: int, log_file: Path) -&gt; bool:</code> |
| L0120 | 计算并保存 &#96;key&#96;（key），供后续逻辑使用，当前位于函数 process_one。 | <code>    key = path.name</code> |
| L0121 | 计算并保存 &#96;success_info&#96;（successinfo），供后续逻辑使用，当前位于函数 process_one。 | <code>    success_info = state.get("success", {}).get(key)</code> |
| L0122 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 process_one。 | <code>    if success_info:</code> |
| L0123 | 结束当前函数并把结果返回给调用方，当前位于函数 process_one。 | <code>        return False</code> |
| L0124 | 计算并保存 &#96;ignored_info&#96;（ignoredinfo），供后续逻辑使用，当前位于函数 process_one。 | <code>    ignored_info = state.get("ignored", {}).get(key)</code> |
| L0125 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 process_one。 | <code>    if ignored_info:</code> |
| L0126 | 结束当前函数并把结果返回给调用方，当前位于函数 process_one。 | <code>        return False</code> |
| L0127 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0128 | 计算并保存 &#96;failed_info&#96;（failedinfo），供后续逻辑使用，当前位于函数 process_one。 | <code>    failed_info = state.get("failed", {}).get(key, {})</code> |
| L0129 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 process_one。 | <code>    if args.max_fail_attempts &gt; 0:</code> |
| L0130 | 计算并保存 &#96;failed_attempts&#96;（failedattempts），供后续逻辑使用，当前位于函数 process_one。 | <code>        failed_attempts = int(failed_info.get("attempts", 0))</code> |
| L0131 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 process_one。 | <code>        if failed_attempts &gt;= args.max_fail_attempts:</code> |
| L0132 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_one。 | <code>            state.setdefault("ignored", {})[key] = {</code> |
| L0133 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_one。 | <code>                "index": idx,</code> |
| L0134 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_one。 | <code>                "path": str(path.resolve()),</code> |
| L0135 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_one。 | <code>                "ignored_at": now_iso(),</code> |
| L0136 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_one。 | <code>                "reason": "max_fail_attempts_reached",</code> |
| L0137 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_one。 | <code>                "attempts": failed_attempts,</code> |
| L0138 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 process_one。 | <code>            }</code> |
| L0139 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_one。 | <code>            state.setdefault("failed", {}).pop(key, None)</code> |
| L0140 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_one。 | <code>            save_state(args.state_file, state)</code> |
| L0141 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 process_one。 | <code>            log(</code> |
| L0142 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_one。 | <code>                f"SKIP #{idx}: {path.name} ignored after {failed_attempts} failed attempts",</code> |
| L0143 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_one。 | <code>                log_file,</code> |
| L0144 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 process_one。 | <code>            )</code> |
| L0145 | 结束当前函数并把结果返回给调用方，当前位于函数 process_one。 | <code>            return False</code> |
| L0146 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0147 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 process_one。 | <code>    if not should_retry_failed(failed_info, args.retry_cooldown):</code> |
| L0148 | 结束当前函数并把结果返回给调用方，当前位于函数 process_one。 | <code>        return False</code> |
| L0149 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0150 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 process_one。 | <code>    if not is_file_stable(path, args.stable_seconds):</code> |
| L0151 | 结束当前函数并把结果返回给调用方，当前位于函数 process_one。 | <code>        return False</code> |
| L0152 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0153 | 计算并保存 &#96;cmd&#96;（cmd），供后续逻辑使用，当前位于函数 process_one。 | <code>    cmd = build_demo_command(args, path)</code> |
| L0154 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 process_one。 | <code>    log(f"START #{idx}: {path}", log_file)</code> |
| L0155 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 process_one。 | <code>    log("CMD: " + " ".join(cmd), log_file)</code> |
| L0156 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0157 | 计算并保存 &#96;result&#96;（结果），供后续逻辑使用，当前位于函数 process_one。 | <code>    result = subprocess.run(</code> |
| L0158 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_one。 | <code>        cmd,</code> |
| L0159 | 计算并保存 &#96;cwd&#96;（cwd），供后续逻辑使用，当前位于函数 process_one。 | <code>        cwd=str(args.project_root),</code> |
| L0160 | 计算并保存 &#96;capture_output&#96;（captureoutput），供后续逻辑使用，当前位于函数 process_one。 | <code>        capture_output=True,</code> |
| L0161 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 process_one。 | <code>        text=True,</code> |
| L0162 | 计算并保存 &#96;encoding&#96;（encoding），供后续逻辑使用，当前位于函数 process_one。 | <code>        encoding="utf-8",</code> |
| L0163 | 计算并保存 &#96;errors&#96;（errors），供后续逻辑使用，当前位于函数 process_one。 | <code>        errors="replace",</code> |
| L0164 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 process_one。 | <code>    )</code> |
| L0165 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0166 | 计算并保存 &#96;demo_log_dir&#96;（demologdir），供后续逻辑使用，当前位于函数 process_one。 | <code>    demo_log_dir = args.output_dir / "daemon_runs"</code> |
| L0167 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_one。 | <code>    demo_log_dir.mkdir(parents=True, exist_ok=True)</code> |
| L0168 | 计算并保存 &#96;run_log&#96;（运行log），供后续逻辑使用，当前位于函数 process_one。 | <code>    run_log = demo_log_dir / f"{path.stem}.{now_iso().replace(':', '-')}.log"</code> |
| L0169 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 process_one。 | <code>    with run_log.open("w", encoding="utf-8") as f:</code> |
| L0170 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_one。 | <code>        f.write("[STDOUT]\n")</code> |
| L0171 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_one。 | <code>        f.write(result.stdout or "")</code> |
| L0172 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_one。 | <code>        f.write("\n\n[STDERR]\n")</code> |
| L0173 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_one。 | <code>        f.write(result.stderr or "")</code> |
| L0174 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0175 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 process_one。 | <code>    if result.returncode == 0:</code> |
| L0176 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_one。 | <code>        state.setdefault("success", {})[key] = {</code> |
| L0177 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_one。 | <code>            "index": idx,</code> |
| L0178 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_one。 | <code>            "path": str(path.resolve()),</code> |
| L0179 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_one。 | <code>            "processed_at": now_iso(),</code> |
| L0180 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_one。 | <code>            "run_log": str(run_log.resolve()),</code> |
| L0181 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 process_one。 | <code>        }</code> |
| L0182 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_one。 | <code>        state.setdefault("failed", {}).pop(key, None)</code> |
| L0183 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_one。 | <code>        save_state(args.state_file, state)</code> |
| L0184 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 process_one。 | <code>        log(f"DONE #{idx}: {path.name} -&gt; success", log_file)</code> |
| L0185 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_one。 | <code>        notify_event(DB_READY_EVENT)</code> |
| L0186 | 结束当前函数并把结果返回给调用方，当前位于函数 process_one。 | <code>        return True</code> |
| L0187 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0188 | 计算并保存 &#96;fail_record&#96;（failrecord），供后续逻辑使用，当前位于函数 process_one。 | <code>    fail_record = state.setdefault("failed", {}).get(key, {})</code> |
| L0189 | 计算并保存 &#96;attempts&#96;（attempts），供后续逻辑使用，当前位于函数 process_one。 | <code>    attempts = int(fail_record.get("attempts", 0)) + 1</code> |
| L0190 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_one。 | <code>    state.setdefault("failed", {})[key] = {</code> |
| L0191 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_one。 | <code>        "index": idx,</code> |
| L0192 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_one。 | <code>        "path": str(path.resolve()),</code> |
| L0193 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_one。 | <code>        "attempts": attempts,</code> |
| L0194 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_one。 | <code>        "last_failed_at": now_iso(),</code> |
| L0195 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_one。 | <code>        "last_returncode": result.returncode,</code> |
| L0196 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_one。 | <code>        "run_log": str(run_log.resolve()),</code> |
| L0197 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 process_one。 | <code>    }</code> |
| L0198 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 process_one。 | <code>    if args.max_fail_attempts &gt; 0 and attempts &gt;= args.max_fail_attempts:</code> |
| L0199 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_one。 | <code>        state.setdefault("ignored", {})[key] = {</code> |
| L0200 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_one。 | <code>            "index": idx,</code> |
| L0201 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_one。 | <code>            "path": str(path.resolve()),</code> |
| L0202 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_one。 | <code>            "ignored_at": now_iso(),</code> |
| L0203 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_one。 | <code>            "reason": "max_fail_attempts_reached",</code> |
| L0204 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_one。 | <code>            "attempts": attempts,</code> |
| L0205 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_one。 | <code>            "last_returncode": result.returncode,</code> |
| L0206 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_one。 | <code>            "run_log": str(run_log.resolve()),</code> |
| L0207 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 process_one。 | <code>        }</code> |
| L0208 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_one。 | <code>        state.setdefault("failed", {}).pop(key, None)</code> |
| L0209 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_one。 | <code>    save_state(args.state_file, state)</code> |
| L0210 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 process_one。 | <code>    if args.max_fail_attempts &gt; 0 and attempts &gt;= args.max_fail_attempts:</code> |
| L0211 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 process_one。 | <code>        log(</code> |
| L0212 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_one。 | <code>            f"FAIL #{idx}: {path.name} rc={result.returncode} attempts={attempts} -&gt; ignored",</code> |
| L0213 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_one。 | <code>            log_file,</code> |
| L0214 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 process_one。 | <code>        )</code> |
| L0215 | 处理前述条件均未命中的情况，当前位于函数 process_one。 | <code>    else:</code> |
| L0216 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 process_one。 | <code>        log(f"FAIL #{idx}: {path.name} rc={result.returncode} attempts={attempts}", log_file)</code> |
| L0217 | 结束当前函数并把结果返回给调用方，当前位于函数 process_one。 | <code>    return True</code> |
| L0218 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0219 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0220 | 定义main函数 &#96;main&#96;，封装可复用业务逻辑。 | <code>def main() -&gt; None:</code> |
| L0221 | 计算并保存 &#96;script_dir&#96;（scriptdir），供后续逻辑使用，当前位于函数 main。 | <code>    script_dir = Path(__file__).resolve().parent</code> |
| L0222 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>    if (script_dir / "app.py").exists():</code> |
| L0223 | 计算并保存 &#96;project_root&#96;（projectroot），供后续逻辑使用，当前位于函数 main。 | <code>        project_root = script_dir</code> |
| L0224 | 当前一条件未命中时继续判断另一条件，当前位于函数 main。 | <code>    elif (script_dir.parent / "app.py").exists():</code> |
| L0225 | 计算并保存 &#96;project_root&#96;（projectroot），供后续逻辑使用，当前位于函数 main。 | <code>        project_root = script_dir.parent</code> |
| L0226 | 处理前述条件均未命中的情况，当前位于函数 main。 | <code>    else:</code> |
| L0227 | 计算并保存 &#96;project_root&#96;（projectroot），供后续逻辑使用，当前位于函数 main。 | <code>        project_root = script_dir</code> |
| L0228 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0229 | 计算并保存 &#96;parser&#96;（parser），供后续逻辑使用，当前位于函数 main。 | <code>    parser = argparse.ArgumentParser(description="常驻监听 input/1.1.n.txt 并自动运行 demo_workflow.py")</code> |
| L0230 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--project-root", default=str(project_root), help="项目根目录")</code> |
| L0231 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--input-dir", default="input", help="监听目录")</code> |
| L0232 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--output-dir", default="output", help="输出目录")</code> |
| L0233 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--demo-script", default="scripts/demo_workflow.py", help="demo workflow 脚本路径")</code> |
| L0234 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--state-file", default="output/demo_daemon_state.json", help="状态文件路径")</code> |
| L0235 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--log-file", default="output/demo_daemon.log", help="守护日志路径")</code> |
| L0236 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--poll-seconds", type=int, default=5, help="轮询间隔秒")</code> |
| L0237 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--stable-seconds", type=int, default=3, help="文件静止判定秒")</code> |
| L0238 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument(</code> |
| L0239 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "--file-order",</code> |
| L0240 | 计算并保存 &#96;choices&#96;（choices），供后续逻辑使用，当前位于函数 main。 | <code>        choices=["newest", "oldest"],</code> |
| L0241 | 计算并保存 &#96;default&#96;（default），供后续逻辑使用，当前位于函数 main。 | <code>        default="newest",</code> |
| L0242 | 计算并保存 &#96;help&#96;（help），供后续逻辑使用，当前位于函数 main。 | <code>        help="处理顺序：newest=新文件优先，oldest=旧文件优先",</code> |
| L0243 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>    )</code> |
| L0244 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--retry-cooldown", type=int, default=30, help="失败重试冷却秒")</code> |
| L0245 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--max-fail-attempts", type=int, default=5, help="单文件失败超过该次数后自动忽略；0=无限重试")</code> |
| L0246 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--once", action="store_true", help="只扫描并处理一次后退出")</code> |
| L0247 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument(</code> |
| L0248 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "--skip-existing-at-start",</code> |
| L0249 | 计算并保存 &#96;action&#96;（action），供后续逻辑使用，当前位于函数 main。 | <code>        action="store_true",</code> |
| L0250 | 计算并保存 &#96;help&#96;（help），供后续逻辑使用，当前位于函数 main。 | <code>        help="启动时将当前已存在的 1.1.n.txt 标记为已处理，仅监听后续新文件",</code> |
| L0251 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>    )</code> |
| L0252 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0253 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--python-exe", default=sys.executable, help="调用 demo_workflow 的 Python")</code> |
| L0254 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--preprocessor", default="", help="传给 demo_workflow 的 preprocessor 路径")</code> |
| L0255 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--model", default="", help="传给 demo_workflow 的 model 路径")</code> |
| L0256 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--label-threshold", type=float, default=0.46)</code> |
| L0257 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--top-k", type=int, default=3)</code> |
| L0258 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--export-min-score", type=float, default=0.3)</code> |
| L0259 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--update-existing-export", action="store_true")</code> |
| L0260 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--enable-v2-gate", action="store_true", help="传给 demo_workflow，启用 v2 检测门控")</code> |
| L0261 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0262 | 计算并保存 &#96;args&#96;（args），供后续逻辑使用，当前位于函数 main。 | <code>    args = parser.parse_args()</code> |
| L0263 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0264 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    args.project_root = Path(args.project_root).resolve()</code> |
| L0265 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    args.input_dir = (args.project_root / args.input_dir).resolve()</code> |
| L0266 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    args.output_dir = (args.project_root / args.output_dir).resolve()</code> |
| L0267 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    args.demo_script = (args.project_root / args.demo_script).resolve()</code> |
| L0268 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    args.state_file = (args.project_root / args.state_file).resolve()</code> |
| L0269 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    args.log_file = (args.project_root / args.log_file).resolve()</code> |
| L0270 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0271 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>    if args.preprocessor:</code> |
| L0272 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        args.preprocessor = Path(args.preprocessor).resolve()</code> |
| L0273 | 处理前述条件均未命中的情况，当前位于函数 main。 | <code>    else:</code> |
| L0274 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        args.preprocessor = None</code> |
| L0275 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>    if args.model:</code> |
| L0276 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        args.model = Path(args.model).resolve()</code> |
| L0277 | 处理前述条件均未命中的情况，当前位于函数 main。 | <code>    else:</code> |
| L0278 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        args.model = None</code> |
| L0279 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0280 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>    if not args.demo_script.exists():</code> |
| L0281 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 main。 | <code>        raise FileNotFoundError(f"demo script 不存在: {args.demo_script}")</code> |
| L0282 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0283 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    args.input_dir.mkdir(parents=True, exist_ok=True)</code> |
| L0284 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    args.output_dir.mkdir(parents=True, exist_ok=True)</code> |
| L0285 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0286 | 计算并保存 &#96;state&#96;（state），供后续逻辑使用，当前位于函数 main。 | <code>    state = load_state(args.state_file)</code> |
| L0287 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0288 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>    if args.skip_existing_at_start and not state.get("success"):</code> |
| L0289 | 计算并保存 &#96;seeded&#96;（seeded），供后续逻辑使用，当前位于函数 main。 | <code>        seeded = 0</code> |
| L0290 | 遍历集合中的数据项并逐项处理，当前位于函数 main。 | <code>        for idx, path in list_input_files(args.input_dir, file_order=args.file_order):</code> |
| L0291 | 计算并保存 &#96;key&#96;（key），供后续逻辑使用，当前位于函数 main。 | <code>            key = path.name</code> |
| L0292 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            state.setdefault("success", {})[key] = {</code> |
| L0293 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                "index": idx,</code> |
| L0294 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                "path": str(path.resolve()),</code> |
| L0295 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                "processed_at": now_iso(),</code> |
| L0296 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                "seeded": True,</code> |
| L0297 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>            }</code> |
| L0298 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            seeded += 1</code> |
| L0299 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        save_state(args.state_file, state)</code> |
| L0300 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>        log(f"seeded existing files: {seeded}", args.log_file)</code> |
| L0301 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0302 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    log("DEMO daemon started", args.log_file)</code> |
| L0303 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    log(f"watch dir: {args.input_dir}", args.log_file)</code> |
| L0304 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    log(f"state file: {args.state_file}", args.log_file)</code> |
| L0305 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    log(f"file order: {args.file_order}", args.log_file)</code> |
| L0306 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0307 | 在条件成立期间循环执行，常用于守护进程轮询，当前位于函数 main。 | <code>    while True:</code> |
| L0308 | 计算并保存 &#96;processed_in_round&#96;（processedinround），供后续逻辑使用，当前位于函数 main。 | <code>        processed_in_round = 0</code> |
| L0309 | 计算并保存 &#96;files&#96;（files），供后续逻辑使用，当前位于函数 main。 | <code>        files = list_input_files(args.input_dir, file_order=args.file_order)</code> |
| L0310 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0311 | 遍历集合中的数据项并逐项处理，当前位于函数 main。 | <code>        for idx, path in files:</code> |
| L0312 | 计算并保存 &#96;did&#96;（did），供后续逻辑使用，当前位于函数 main。 | <code>            did = process_one(args, state, path, idx, args.log_file)</code> |
| L0313 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>            if did:</code> |
| L0314 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                processed_in_round += 1</code> |
| L0315 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0316 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>        if args.once:</code> |
| L0317 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>            log(f"ONCE done. processed_in_round={processed_in_round}", args.log_file)</code> |
| L0318 | 控制当前循环或占位分支的执行流程，当前位于函数 main。 | <code>            break</code> |
| L0319 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0320 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        wait_event(DETECTION_READY_EVENT, max(args.poll_seconds, 1))</code> |
| L0321 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0322 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0323 | 判断条件是否成立，成立时进入对应处理分支。 | <code>if __name__ == "__main__":</code> |
| L0324 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    main()</code> |
| L0325 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0326 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
