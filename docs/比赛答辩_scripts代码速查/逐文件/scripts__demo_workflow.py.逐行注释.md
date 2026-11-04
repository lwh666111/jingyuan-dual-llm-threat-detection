# `scripts/demo_workflow.py` 逐行注释

**脚本用途：** 执行旧模型兼容筛选、候选导出和检测结果组织。

**源码行数：** 353　**函数/类数量：** 14

| 行号 | 中文说明 | 原始源码 |
|---:|---|---|
| L0001 | 导入后续逻辑所需的模块、类或函数：&#96;import argparse&#96;。 | <code>import argparse</code> |
| L0002 | 导入后续逻辑所需的模块、类或函数：&#96;import csv&#96;。 | <code>import csv</code> |
| L0003 | 导入后续逻辑所需的模块、类或函数：&#96;import json&#96;。 | <code>import json</code> |
| L0004 | 导入后续逻辑所需的模块、类或函数：&#96;import subprocess&#96;。 | <code>import subprocess</code> |
| L0005 | 导入后续逻辑所需的模块、类或函数：&#96;import sys&#96;。 | <code>import sys</code> |
| L0006 | 导入后续逻辑所需的模块、类或函数：&#96;from pathlib import Path&#96;。 | <code>from pathlib import Path</code> |
| L0007 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0008 | 计算并保存 &#96;SCRIPT_DIR&#96;（SCRIPTDIR），供后续逻辑使用。 | <code>SCRIPT_DIR = Path(__file__).resolve().parent</code> |
| L0009 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0010 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0011 | 定义检测projectroot函数 &#96;detect_project_root&#96;，封装可复用业务逻辑。 | <code>def detect_project_root() -&gt; Path:</code> |
| L0012 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 detect_project_root。 | <code>    if (SCRIPT_DIR / "app.py").exists():</code> |
| L0013 | 结束当前函数并把结果返回给调用方，当前位于函数 detect_project_root。 | <code>        return SCRIPT_DIR</code> |
| L0014 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 detect_project_root。 | <code>    if (SCRIPT_DIR.parent / "app.py").exists():</code> |
| L0015 | 结束当前函数并把结果返回给调用方，当前位于函数 detect_project_root。 | <code>        return SCRIPT_DIR.parent</code> |
| L0016 | 结束当前函数并把结果返回给调用方，当前位于函数 detect_project_root。 | <code>    return SCRIPT_DIR</code> |
| L0017 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0018 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0019 | 计算并保存 &#96;PROJECT_ROOT&#96;（PROJECTROOT），供后续逻辑使用。 | <code>PROJECT_ROOT = detect_project_root()</code> |
| L0020 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0021 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0022 | 定义printsteptitle函数 &#96;print_step_title&#96;，封装可复用业务逻辑。 | <code>def print_step_title(title: str):</code> |
| L0023 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 print_step_title。 | <code>    print("\n" + "=" * 80)</code> |
| L0024 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 print_step_title。 | <code>    print(title)</code> |
| L0025 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 print_step_title。 | <code>    print("=" * 80)</code> |
| L0026 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0027 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0028 | 定义safeconsoletext函数 &#96;_safe_console_text&#96;，封装可复用业务逻辑。 | <code>def _safe_console_text(text: str) -&gt; str:</code> |
| L0029 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _safe_console_text。 | <code>    if text is None:</code> |
| L0030 | 结束当前函数并把结果返回给调用方，当前位于函数 _safe_console_text。 | <code>        return ""</code> |
| L0031 | 计算并保存 &#96;enc&#96;（enc），供后续逻辑使用，当前位于函数 _safe_console_text。 | <code>    enc = sys.stdout.encoding or "utf-8"</code> |
| L0032 | 结束当前函数并把结果返回给调用方，当前位于函数 _safe_console_text。 | <code>    return text.encode(enc, errors="replace").decode(enc, errors="replace")</code> |
| L0033 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0034 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0035 | 定义解析并确定default模型paths函数 &#96;resolve_default_model_paths&#96;，封装可复用业务逻辑。 | <code>def resolve_default_model_paths():</code> |
| L0036 | 计算并保存 &#96;local_models&#96;（localmodels），供后续逻辑使用，当前位于函数 resolve_default_model_paths。 | <code>    local_models = PROJECT_ROOT / "models"</code> |
| L0037 | 计算并保存 &#96;local_pre&#96;（localpre），供后续逻辑使用，当前位于函数 resolve_default_model_paths。 | <code>    local_pre = local_models / "preprocessor.joblib"</code> |
| L0038 | 计算并保存 &#96;local_mdl&#96;（localmdl），供后续逻辑使用，当前位于函数 resolve_default_model_paths。 | <code>    local_mdl = local_models / "best_mlp.pth"</code> |
| L0039 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 resolve_default_model_paths。 | <code>    if local_pre.exists() and local_mdl.exists():</code> |
| L0040 | 结束当前函数并把结果返回给调用方，当前位于函数 resolve_default_model_paths。 | <code>        return local_pre, local_mdl</code> |
| L0041 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0042 | 计算并保存 &#96;fallback_models&#96;（fallbackmodels），供后续逻辑使用，当前位于函数 resolve_default_model_paths。 | <code>    fallback_models = PROJECT_ROOT.parent / "traffic_mlp" / "models"</code> |
| L0043 | 结束当前函数并把结果返回给调用方，当前位于函数 resolve_default_model_paths。 | <code>    return fallback_models / "preprocessor.joblib", fallback_models / "best_mlp.pth"</code> |
| L0044 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0045 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0046 | 定义scriptpath函数 &#96;script_path&#96;，封装可复用业务逻辑。 | <code>def script_path(name: str) -&gt; Path:</code> |
| L0047 | 结束当前函数并把结果返回给调用方，当前位于函数 script_path。 | <code>    return SCRIPT_DIR / name</code> |
| L0048 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0049 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0050 | 定义运行command函数 &#96;run_command&#96;，封装可复用业务逻辑。 | <code>def run_command(cmd, cwd=None):</code> |
| L0051 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_command。 | <code>    print_step_title("执行命令")</code> |
| L0052 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 run_command。 | <code>    print(" ".join(str(x) for x in cmd))</code> |
| L0053 | 计算并保存 &#96;result&#96;（结果），供后续逻辑使用，当前位于函数 run_command。 | <code>    result = subprocess.run(</code> |
| L0054 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_command。 | <code>        cmd,</code> |
| L0055 | 计算并保存 &#96;cwd&#96;（cwd），供后续逻辑使用，当前位于函数 run_command。 | <code>        cwd=cwd,</code> |
| L0056 | 计算并保存 &#96;capture_output&#96;（captureoutput），供后续逻辑使用，当前位于函数 run_command。 | <code>        capture_output=True,</code> |
| L0057 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 run_command。 | <code>        text=True,</code> |
| L0058 | 计算并保存 &#96;encoding&#96;（encoding），供后续逻辑使用，当前位于函数 run_command。 | <code>        encoding="utf-8",</code> |
| L0059 | 计算并保存 &#96;errors&#96;（errors），供后续逻辑使用，当前位于函数 run_command。 | <code>        errors="replace",</code> |
| L0060 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 run_command。 | <code>    )</code> |
| L0061 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 run_command。 | <code>    print("\n[STDOUT]")</code> |
| L0062 | 计算并保存 &#96;stdout_text&#96;（stdouttext），供后续逻辑使用，当前位于函数 run_command。 | <code>    stdout_text = result.stdout if result.stdout.strip() else "(无)"</code> |
| L0063 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 run_command。 | <code>    print(_safe_console_text(stdout_text))</code> |
| L0064 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 run_command。 | <code>    print("\n[STDERR]")</code> |
| L0065 | 计算并保存 &#96;stderr_text&#96;（stderrtext），供后续逻辑使用，当前位于函数 run_command。 | <code>    stderr_text = result.stderr if result.stderr.strip() else "(无)"</code> |
| L0066 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 run_command。 | <code>    print(_safe_console_text(stderr_text))</code> |
| L0067 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 run_command。 | <code>    if result.returncode != 0:</code> |
| L0068 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 run_command。 | <code>        raise RuntimeError(f"命令执行失败，返回码={result.returncode}")</code> |
| L0069 | 结束当前函数并把结果返回给调用方，当前位于函数 run_command。 | <code>    return result</code> |
| L0070 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0071 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0072 | 定义previewjsonl函数 &#96;preview_jsonl&#96;，封装可复用业务逻辑。 | <code>def preview_jsonl(path: Path, limit=3, keys=None):</code> |
| L0073 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 preview_jsonl。 | <code>    print_step_title(f"预览 JSONL: {path}")</code> |
| L0074 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 preview_jsonl。 | <code>    if not path.exists():</code> |
| L0075 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 preview_jsonl。 | <code>        print("文件不存在")</code> |
| L0076 | 结束当前函数并把结果返回给调用方，当前位于函数 preview_jsonl。 | <code>        return</code> |
| L0077 | 计算并保存 &#96;count&#96;（count），供后续逻辑使用，当前位于函数 preview_jsonl。 | <code>    count = 0</code> |
| L0078 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 preview_jsonl。 | <code>    with path.open("r", encoding="utf-8") as f:</code> |
| L0079 | 遍历集合中的数据项并逐项处理，当前位于函数 preview_jsonl。 | <code>        for line in f:</code> |
| L0080 | 计算并保存 &#96;line&#96;（line），供后续逻辑使用，当前位于函数 preview_jsonl。 | <code>            line = line.strip()</code> |
| L0081 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 preview_jsonl。 | <code>            if not line:</code> |
| L0082 | 控制当前循环或占位分支的执行流程，当前位于函数 preview_jsonl。 | <code>                continue</code> |
| L0083 | 计算并保存 &#96;obj&#96;（obj），供后续逻辑使用，当前位于函数 preview_jsonl。 | <code>            obj = json.loads(line)</code> |
| L0084 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 preview_jsonl。 | <code>            if keys:</code> |
| L0085 | 计算并保存 &#96;obj&#96;（obj），供后续逻辑使用，当前位于函数 preview_jsonl。 | <code>                obj = {k: obj.get(k) for k in keys}</code> |
| L0086 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 preview_jsonl。 | <code>            print(json.dumps(obj, ensure_ascii=False, indent=2))</code> |
| L0087 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 preview_jsonl。 | <code>            count += 1</code> |
| L0088 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 preview_jsonl。 | <code>            if count &gt;= limit:</code> |
| L0089 | 控制当前循环或占位分支的执行流程，当前位于函数 preview_jsonl。 | <code>                break</code> |
| L0090 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 preview_jsonl。 | <code>    if count == 0:</code> |
| L0091 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 preview_jsonl。 | <code>        print("(空文件)")</code> |
| L0092 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0093 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0094 | 定义previewcsv函数 &#96;preview_csv&#96;，封装可复用业务逻辑。 | <code>def preview_csv(path: Path, limit=3):</code> |
| L0095 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 preview_csv。 | <code>    print_step_title(f"预览 CSV: {path}")</code> |
| L0096 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 preview_csv。 | <code>    if not path.exists():</code> |
| L0097 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 preview_csv。 | <code>        print("文件不存在")</code> |
| L0098 | 结束当前函数并把结果返回给调用方，当前位于函数 preview_csv。 | <code>        return</code> |
| L0099 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 preview_csv。 | <code>    with path.open("r", encoding="utf-8-sig", newline="") as f:</code> |
| L0100 | 计算并保存 &#96;reader&#96;（reader），供后续逻辑使用，当前位于函数 preview_csv。 | <code>        reader = csv.DictReader(f)</code> |
| L0101 | 遍历集合中的数据项并逐项处理，当前位于函数 preview_csv。 | <code>        for idx, row in enumerate(reader):</code> |
| L0102 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 preview_csv。 | <code>            print(json.dumps(row, ensure_ascii=False, indent=2))</code> |
| L0103 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 preview_csv。 | <code>            if idx + 1 &gt;= limit:</code> |
| L0104 | 控制当前循环或占位分支的执行流程，当前位于函数 preview_csv。 | <code>                break</code> |
| L0105 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0106 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0107 | 定义countjsonl函数 &#96;count_jsonl&#96;，封装可复用业务逻辑。 | <code>def count_jsonl(path: Path) -&gt; int:</code> |
| L0108 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 count_jsonl。 | <code>    if not path.exists():</code> |
| L0109 | 结束当前函数并把结果返回给调用方，当前位于函数 count_jsonl。 | <code>        return 0</code> |
| L0110 | 计算并保存 &#96;count&#96;（count），供后续逻辑使用，当前位于函数 count_jsonl。 | <code>    count = 0</code> |
| L0111 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 count_jsonl。 | <code>    with path.open("r", encoding="utf-8") as f:</code> |
| L0112 | 遍历集合中的数据项并逐项处理，当前位于函数 count_jsonl。 | <code>        for line in f:</code> |
| L0113 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 count_jsonl。 | <code>            if line.strip():</code> |
| L0114 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 count_jsonl。 | <code>                count += 1</code> |
| L0115 | 结束当前函数并把结果返回给调用方，当前位于函数 count_jsonl。 | <code>    return count</code> |
| L0116 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0117 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0118 | 定义countcsv数据库记录函数 &#96;count_csv_rows&#96;，封装可复用业务逻辑。 | <code>def count_csv_rows(path: Path) -&gt; int:</code> |
| L0119 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 count_csv_rows。 | <code>    if not path.exists():</code> |
| L0120 | 结束当前函数并把结果返回给调用方，当前位于函数 count_csv_rows。 | <code>        return 0</code> |
| L0121 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 count_csv_rows。 | <code>    with path.open("r", encoding="utf-8-sig", newline="") as f:</code> |
| L0122 | 计算并保存 &#96;reader&#96;（reader），供后续逻辑使用，当前位于函数 count_csv_rows。 | <code>        reader = csv.DictReader(f)</code> |
| L0123 | 结束当前函数并把结果返回给调用方，当前位于函数 count_csv_rows。 | <code>        return sum(1 for _ in reader)</code> |
| L0124 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0125 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0126 | 定义caseidsortkey函数 &#96;_case_id_sort_key&#96;，封装可复用业务逻辑。 | <code>def _case_id_sort_key(case_id: str):</code> |
| L0127 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _case_id_sort_key。 | <code>    if isinstance(case_id, str) and case_id.startswith("b."):</code> |
| L0128 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 _case_id_sort_key。 | <code>        try:</code> |
| L0129 | 结束当前函数并把结果返回给调用方，当前位于函数 _case_id_sort_key。 | <code>            return int(case_id.split(".", 1)[1])</code> |
| L0130 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 _case_id_sort_key。 | <code>        except Exception:</code> |
| L0131 | 结束当前函数并把结果返回给调用方，当前位于函数 _case_id_sort_key。 | <code>            return 10**9</code> |
| L0132 | 结束当前函数并把结果返回给调用方，当前位于函数 _case_id_sort_key。 | <code>    return 10**9</code> |
| L0133 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0134 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0135 | 定义加载manifestcaseids函数 &#96;load_manifest_case_ids&#96;，封装可复用业务逻辑。 | <code>def load_manifest_case_ids(manifest_path: Path):</code> |
| L0136 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 load_manifest_case_ids。 | <code>    if not manifest_path.exists():</code> |
| L0137 | 结束当前函数并把结果返回给调用方，当前位于函数 load_manifest_case_ids。 | <code>        return []</code> |
| L0138 | 计算并保存 &#96;ids&#96;（ids），供后续逻辑使用，当前位于函数 load_manifest_case_ids。 | <code>    ids = []</code> |
| L0139 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 load_manifest_case_ids。 | <code>    with manifest_path.open("r", encoding="utf-8") as f:</code> |
| L0140 | 遍历集合中的数据项并逐项处理，当前位于函数 load_manifest_case_ids。 | <code>        for line in f:</code> |
| L0141 | 计算并保存 &#96;line&#96;（line），供后续逻辑使用，当前位于函数 load_manifest_case_ids。 | <code>            line = line.strip()</code> |
| L0142 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 load_manifest_case_ids。 | <code>            if not line:</code> |
| L0143 | 控制当前循环或占位分支的执行流程，当前位于函数 load_manifest_case_ids。 | <code>                continue</code> |
| L0144 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 load_manifest_case_ids。 | <code>            try:</code> |
| L0145 | 计算并保存 &#96;obj&#96;（obj），供后续逻辑使用，当前位于函数 load_manifest_case_ids。 | <code>                obj = json.loads(line)</code> |
| L0146 | 计算并保存 &#96;cid&#96;（cid），供后续逻辑使用，当前位于函数 load_manifest_case_ids。 | <code>                cid = obj.get("case_id")</code> |
| L0147 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 load_manifest_case_ids。 | <code>                if cid:</code> |
| L0148 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 load_manifest_case_ids。 | <code>                    ids.append(str(cid))</code> |
| L0149 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 load_manifest_case_ids。 | <code>            except Exception:</code> |
| L0150 | 控制当前循环或占位分支的执行流程，当前位于函数 load_manifest_case_ids。 | <code>                continue</code> |
| L0151 | 计算并保存 &#96;ids&#96;（ids），供后续逻辑使用，当前位于函数 load_manifest_case_ids。 | <code>    ids = list(dict.fromkeys(ids))</code> |
| L0152 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_manifest_case_ids。 | <code>    ids.sort(key=_case_id_sort_key)</code> |
| L0153 | 结束当前函数并把结果返回给调用方，当前位于函数 load_manifest_case_ids。 | <code>    return ids</code> |
| L0154 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0155 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0156 | 定义requirefile函数 &#96;require_file&#96;，封装可复用业务逻辑。 | <code>def require_file(path: Path, description: str):</code> |
| L0157 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 require_file。 | <code>    if not path.exists():</code> |
| L0158 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 require_file。 | <code>        raise FileNotFoundError(f"{description} 不存在: {path}")</code> |
| L0159 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 require_file。 | <code>    print(f"[OK] {description}: {path}")</code> |
| L0160 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0161 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0162 | 定义main函数 &#96;main&#96;，封装可复用业务逻辑。 | <code>def main():</code> |
| L0163 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    default_pre, default_model = resolve_default_model_paths()</code> |
| L0164 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0165 | 计算并保存 &#96;parser&#96;（parser），供后续逻辑使用，当前位于函数 main。 | <code>    parser = argparse.ArgumentParser(</code> |
| L0166 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 main。 | <code>        description="新工作流演示：txt -&gt; old_model_input -&gt; old_model -&gt; rerank -&gt; demo_candidates"</code> |
| L0167 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>    )</code> |
| L0168 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--input-txt", required=True, help="输入 Wireshark txt 文件路径，例如 input/1.1.2.txt")</code> |
| L0169 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--preprocessor", default=str(default_pre), help="旧 preprocessor.joblib 路径")</code> |
| L0170 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--model", default=str(default_model), help="旧 best_mlp.pth 路径")</code> |
| L0171 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--label-threshold", type=float, default=0.35, help="compat mode 标签阈值")</code> |
| L0172 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--top-k", type=int, default=3, help="demo candidates 输出条数")</code> |
| L0173 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--export-min-score", type=float, default=0.3, help="导出到 result 的最低 raw_score 阈值")</code> |
| L0174 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--update-existing-export", action="store_true", help="导出到 result 时若已存在则覆盖更新")</code> |
| L0175 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--enable-v2-gate", action="store_true", help="启用 v2 Payload/POC/行为融合门控")</code> |
| L0176 | 计算并保存 &#96;args&#96;（args），供后续逻辑使用，当前位于函数 main。 | <code>    args = parser.parse_args()</code> |
| L0177 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0178 | 计算并保存 &#96;input_txt&#96;（inputtxt），供后续逻辑使用，当前位于函数 main。 | <code>    input_txt = Path(args.input_txt).resolve()</code> |
| L0179 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>    if not input_txt.exists():</code> |
| L0180 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 main。 | <code>        raise FileNotFoundError(f"输入文件不存在: {input_txt}")</code> |
| L0181 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0182 | 计算并保存 &#96;preprocessor_path&#96;（preprocessorpath），供后续逻辑使用，当前位于函数 main。 | <code>    preprocessor_path = Path(args.preprocessor).resolve()</code> |
| L0183 | 计算并保存 &#96;model_path&#96;（模型path），供后续逻辑使用，当前位于函数 main。 | <code>    model_path = Path(args.model).resolve()</code> |
| L0184 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0185 | 计算并保存 &#96;required_scripts&#96;（requiredscripts），供后续逻辑使用，当前位于函数 main。 | <code>    required_scripts = [</code> |
| L0186 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "extract_old_model_features_from_txt.py",</code> |
| L0187 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "run_old_model_direct.py",</code> |
| L0188 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 main。 | <code>        "rerank_model_result.py",</code> |
| L0189 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "build_demo_candidates.py",</code> |
| L0190 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "export_demo_candidates_to_result.py",</code> |
| L0191 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>    ]</code> |
| L0192 | 计算并保存 &#96;missing_scripts&#96;（missingscripts），供后续逻辑使用，当前位于函数 main。 | <code>    missing_scripts = [s for s in required_scripts if not script_path(s).exists()]</code> |
| L0193 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>    if missing_scripts:</code> |
| L0194 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 main。 | <code>        raise FileNotFoundError(f"缺少脚本: {missing_scripts}")</code> |
| L0195 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0196 | 计算并保存 &#96;file_id&#96;（fileid），供后续逻辑使用，当前位于函数 main。 | <code>    file_id = input_txt.stem</code> |
| L0197 | 计算并保存 &#96;output_dir&#96;（outputdir），供后续逻辑使用，当前位于函数 main。 | <code>    output_dir = PROJECT_ROOT / "output" / f"demo_{file_id}"</code> |
| L0198 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    output_dir.mkdir(parents=True, exist_ok=True)</code> |
| L0199 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0200 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    print_step_title("演示模式说明")</code> |
| L0201 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print("当前为旧模型兼容演示模式（新直提链路），输出仅用于流程验证，不代表最终检测效果。")</code> |
| L0202 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print(f"输入文件: {input_txt}")</code> |
| L0203 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print(f"file_id: {file_id}")</code> |
| L0204 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print(f"输出目录: {output_dir}")</code> |
| L0205 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print(f"旧预处理器: {preprocessor_path}")</code> |
| L0206 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print(f"旧模型: {model_path}")</code> |
| L0207 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0208 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    require_file(preprocessor_path, "旧预处理器")</code> |
| L0209 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    require_file(model_path, "旧模型")</code> |
| L0210 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0211 | 计算并保存 &#96;old_schema_json&#96;（oldschemajson），供后续逻辑使用，当前位于函数 main。 | <code>    old_schema_json = output_dir / "old_preprocessor_schema.json"</code> |
| L0212 | 计算并保存 &#96;old_input_csv&#96;（oldinputcsv），供后续逻辑使用，当前位于函数 main。 | <code>    old_input_csv = output_dir / f"{file_id}.old_model_input.csv"</code> |
| L0213 | 计算并保存 &#96;raw_index_jsonl&#96;（rawindexjsonl），供后续逻辑使用，当前位于函数 main。 | <code>    raw_index_jsonl = output_dir / f"{file_id}.raw_index.jsonl"</code> |
| L0214 | 计算并保存 &#96;model_result_jsonl&#96;（模型结果jsonl），供后续逻辑使用，当前位于函数 main。 | <code>    model_result_jsonl = output_dir / f"{file_id}.model_result.jsonl"</code> |
| L0215 | 计算并保存 &#96;model_result_csv&#96;（模型结果csv），供后续逻辑使用，当前位于函数 main。 | <code>    model_result_csv = output_dir / f"{file_id}.model_result.csv"</code> |
| L0216 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 main。 | <code>    reranked_jsonl = output_dir / f"{file_id}.model_result_reranked.jsonl"</code> |
| L0217 | 计算并保存 &#96;demo_candidates_jsonl&#96;（democandidatesjsonl），供后续逻辑使用，当前位于函数 main。 | <code>    demo_candidates_jsonl = output_dir / f"{file_id}.demo_candidates.jsonl"</code> |
| L0218 | 计算并保存 &#96;result_dir&#96;（结果dir），供后续逻辑使用，当前位于函数 main。 | <code>    result_dir = PROJECT_ROOT / "result"</code> |
| L0219 | 计算并保存 &#96;manifest_jsonl&#96;（manifestjsonl），供后续逻辑使用，当前位于函数 main。 | <code>    manifest_jsonl = result_dir / "manifest.jsonl"</code> |
| L0220 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0221 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    print_step_title("Step 1 / 5 - extract_old_model_features_from_txt.py")</code> |
| L0222 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    run_command(</code> |
| L0223 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        [</code> |
| L0224 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            sys.executable,</code> |
| L0225 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            str(script_path("extract_old_model_features_from_txt.py")),</code> |
| L0226 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "--input",</code> |
| L0227 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            str(input_txt),</code> |
| L0228 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "--preprocessor",</code> |
| L0229 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            str(preprocessor_path),</code> |
| L0230 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "--output-dir",</code> |
| L0231 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            str(output_dir),</code> |
| L0232 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>        ]</code> |
| L0233 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>    )</code> |
| L0234 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    require_file(old_schema_json, "旧预处理器 schema")</code> |
| L0235 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    require_file(old_input_csv, "old_model_input csv")</code> |
| L0236 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    require_file(raw_index_jsonl, "raw_index jsonl")</code> |
| L0237 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    preview_csv(old_input_csv, limit=3)</code> |
| L0238 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    preview_jsonl(raw_index_jsonl, limit=3, keys=["file_id", "seq_id", "method", "uri", "status_code"])</code> |
| L0239 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0240 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    print_step_title("Step 2 / 5 - run_old_model_direct.py")</code> |
| L0241 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    run_command(</code> |
| L0242 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        [</code> |
| L0243 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            sys.executable,</code> |
| L0244 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            str(script_path("run_old_model_direct.py")),</code> |
| L0245 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "--input",</code> |
| L0246 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            str(old_input_csv),</code> |
| L0247 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "--preprocessor",</code> |
| L0248 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            str(preprocessor_path),</code> |
| L0249 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "--model",</code> |
| L0250 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            str(model_path),</code> |
| L0251 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "--output-jsonl",</code> |
| L0252 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            str(model_result_jsonl),</code> |
| L0253 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "--output-csv",</code> |
| L0254 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            str(model_result_csv),</code> |
| L0255 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "--label-threshold",</code> |
| L0256 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            str(args.label_threshold),</code> |
| L0257 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>        ]</code> |
| L0258 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>    )</code> |
| L0259 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    require_file(model_result_jsonl, "model_result jsonl")</code> |
| L0260 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    require_file(model_result_csv, "model_result csv")</code> |
| L0261 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    preview_jsonl(model_result_jsonl, limit=5, keys=["file_id", "seq_id", "score", "label", "model_name"])</code> |
| L0262 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0263 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 main。 | <code>    print_step_title("Step 3 / 5 - rerank_model_result.py")</code> |
| L0264 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    run_command(</code> |
| L0265 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        [</code> |
| L0266 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            sys.executable,</code> |
| L0267 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 main。 | <code>            str(script_path("rerank_model_result.py")),</code> |
| L0268 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "--input",</code> |
| L0269 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            str(model_result_jsonl),</code> |
| L0270 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "--output",</code> |
| L0271 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 main。 | <code>            str(reranked_jsonl),</code> |
| L0272 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>        ]</code> |
| L0273 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>    )</code> |
| L0274 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 main。 | <code>    require_file(reranked_jsonl, "reranked model_result jsonl")</code> |
| L0275 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 main。 | <code>    preview_jsonl(reranked_jsonl, limit=5, keys=["file_id", "seq_id", "raw_score", "norm_score", "rank", "label"])</code> |
| L0276 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0277 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    print_step_title("Step 4 / 5 - build_demo_candidates.py")</code> |
| L0278 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    run_command(</code> |
| L0279 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        [</code> |
| L0280 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            sys.executable,</code> |
| L0281 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            str(script_path("build_demo_candidates.py")),</code> |
| L0282 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "--parsed",</code> |
| L0283 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            str(raw_index_jsonl),</code> |
| L0284 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "--model-input",</code> |
| L0285 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            str(raw_index_jsonl),</code> |
| L0286 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 main。 | <code>            "--reranked-result",</code> |
| L0287 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 main。 | <code>            str(reranked_jsonl),</code> |
| L0288 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "--output",</code> |
| L0289 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            str(demo_candidates_jsonl),</code> |
| L0290 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "--top-k",</code> |
| L0291 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            str(args.top_k),</code> |
| L0292 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>        ]</code> |
| L0293 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>    )</code> |
| L0294 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    require_file(demo_candidates_jsonl, "demo_candidates jsonl")</code> |
| L0295 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    preview_jsonl(</code> |
| L0296 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        demo_candidates_jsonl,</code> |
| L0297 | 计算并保存 &#96;limit&#96;（limit），供后续逻辑使用，当前位于函数 main。 | <code>        limit=3,</code> |
| L0298 | 计算并保存 &#96;keys&#96;（keys），供后续逻辑使用，当前位于函数 main。 | <code>        keys=["file_id", "seq_id", "rank", "raw_score", "norm_score", "method", "uri", "status_code"],</code> |
| L0299 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>    )</code> |
| L0300 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0301 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    print_step_title("Step 5 / 5 - export_demo_candidates_to_result.py")</code> |
| L0302 | 计算并保存 &#96;before_case_ids&#96;（beforecaseids），供后续逻辑使用，当前位于函数 main。 | <code>    before_case_ids = load_manifest_case_ids(manifest_jsonl)</code> |
| L0303 | 计算并保存 &#96;export_cmd&#96;（exportcmd），供后续逻辑使用，当前位于函数 main。 | <code>    export_cmd = [</code> |
| L0304 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        sys.executable,</code> |
| L0305 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        str(script_path("export_demo_candidates_to_result.py")),</code> |
| L0306 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "--input",</code> |
| L0307 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        str(demo_candidates_jsonl),</code> |
| L0308 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "--result-dir",</code> |
| L0309 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        str(result_dir),</code> |
| L0310 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "--min-score",</code> |
| L0311 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        str(args.export_min_score),</code> |
| L0312 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>    ]</code> |
| L0313 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>    if args.update_existing_export:</code> |
| L0314 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 main。 | <code>        export_cmd.append("--update-existing")</code> |
| L0315 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>    if args.enable_v2_gate:</code> |
| L0316 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 main。 | <code>        export_cmd.append("--enable-v2-gate")</code> |
| L0317 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0318 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    run_command(export_cmd)</code> |
| L0319 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    require_file(manifest_jsonl, "result manifest")</code> |
| L0320 | 计算并保存 &#96;after_case_ids&#96;（aftercaseids），供后续逻辑使用，当前位于函数 main。 | <code>    after_case_ids = load_manifest_case_ids(manifest_jsonl)</code> |
| L0321 | 计算并保存 &#96;before_case_set&#96;（beforecaseset），供后续逻辑使用，当前位于函数 main。 | <code>    before_case_set = set(before_case_ids)</code> |
| L0322 | 计算并保存 &#96;new_case_ids&#96;（newcaseids），供后续逻辑使用，当前位于函数 main。 | <code>    new_case_ids = [cid for cid in after_case_ids if cid not in before_case_set]</code> |
| L0323 | 计算并保存 &#96;result_export_count&#96;（结果exportcount），供后续逻辑使用，当前位于函数 main。 | <code>    result_export_count = len(new_case_ids)</code> |
| L0324 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0325 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    print_step_title("工作流总结")</code> |
| L0326 | 计算并保存 &#96;extracted_count&#96;（extractedcount），供后续逻辑使用，当前位于函数 main。 | <code>    extracted_count = count_jsonl(raw_index_jsonl)</code> |
| L0327 | 计算并保存 &#96;old_input_count&#96;（oldinputcount），供后续逻辑使用，当前位于函数 main。 | <code>    old_input_count = count_csv_rows(old_input_csv)</code> |
| L0328 | 计算并保存 &#96;model_result_count&#96;（模型结果count），供后续逻辑使用，当前位于函数 main。 | <code>    model_result_count = count_jsonl(model_result_jsonl)</code> |
| L0329 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 main。 | <code>    reranked_count = count_jsonl(reranked_jsonl)</code> |
| L0330 | 计算并保存 &#96;demo_candidates_count&#96;（democandidatescount），供后续逻辑使用，当前位于函数 main。 | <code>    demo_candidates_count = count_jsonl(demo_candidates_jsonl)</code> |
| L0331 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print(f"提取请求数量(raw_index): {extracted_count}")</code> |
| L0332 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print(f"old_model_input 行数: {old_input_count}")</code> |
| L0333 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print(f"model_result 数量: {model_result_count}")</code> |
| L0334 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 main。 | <code>    print(f"reranked 数量: {reranked_count}")</code> |
| L0335 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print(f"demo_candidates 数量: {demo_candidates_count}")</code> |
| L0336 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print(f"result 导出阈值(raw_score): {args.export_min_score}")</code> |
| L0337 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print(f"result 新导出 case 数量: {result_export_count}")</code> |
| L0338 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print(f"result 新导出的 case_id: {new_case_ids if new_case_ids else '无'}")</code> |
| L0339 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0340 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print("\n前 3 条 demo_candidates 摘要：")</code> |
| L0341 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    preview_jsonl(</code> |
| L0342 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        demo_candidates_jsonl,</code> |
| L0343 | 计算并保存 &#96;limit&#96;（limit），供后续逻辑使用，当前位于函数 main。 | <code>        limit=3,</code> |
| L0344 | 计算并保存 &#96;keys&#96;（keys），供后续逻辑使用，当前位于函数 main。 | <code>        keys=["file_id", "seq_id", "rank", "raw_score", "norm_score", "uri", "method"],</code> |
| L0345 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>    )</code> |
| L0346 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0347 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    print_step_title("演示完成")</code> |
| L0348 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print("新工作流已执行完毕。")</code> |
| L0349 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print(f"所有结果输出在: {output_dir}")</code> |
| L0350 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0351 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0352 | 判断条件是否成立，成立时进入对应处理分支。 | <code>if __name__ == "__main__":</code> |
| L0353 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    main()</code> |
