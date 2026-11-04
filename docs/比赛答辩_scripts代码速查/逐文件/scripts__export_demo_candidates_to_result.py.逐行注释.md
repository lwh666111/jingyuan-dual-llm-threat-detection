# `scripts/export_demo_candidates_to_result.py` 逐行注释

**脚本用途：** 辅助脚本：根据文件名 `export_demo_candidates_to_result.py` 完成对应的数据处理或运维任务。

**源码行数：** 352　**函数/类数量：** 8

| 行号 | 中文说明 | 原始源码 |
|---:|---|---|
| L0001 | 导入后续逻辑所需的模块、类或函数：&#96;import argparse&#96;。 | <code>import argparse</code> |
| L0002 | 导入后续逻辑所需的模块、类或函数：&#96;import json&#96;。 | <code>import json</code> |
| L0003 | 导入后续逻辑所需的模块、类或函数：&#96;import re&#96;。 | <code>import re</code> |
| L0004 | 导入后续逻辑所需的模块、类或函数：&#96;from datetime import datetime&#96;。 | <code>from datetime import datetime</code> |
| L0005 | 导入后续逻辑所需的模块、类或函数：&#96;from pathlib import Path&#96;。 | <code>from pathlib import Path</code> |
| L0006 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0007 | 导入后续逻辑所需的模块、类或函数：&#96;from web_attack_rules import apply_rule_signal, detect_request_attack, is_plain_auth_attempt&#96;。 | <code>from web_attack_rules import apply_rule_signal, detect_request_attack, is_plain_auth_attempt</code> |
| L0008 | 导入后续逻辑所需的模块、类或函数：&#96;from security_detection_v2 import DetectionEngineV2&#96;。 | <code>from security_detection_v2 import DetectionEngineV2</code> |
| L0009 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0010 | 计算并保存 &#96;DEFAULT_LLM_TASK&#96;（DEFAULTLLMTASK），供后续逻辑使用。 | <code>DEFAULT_LLM_TASK = (</code> |
| L0011 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "\u8bf7\u5224\u65ad\u8be5\u8bf7\u6c42\u662f\u5426\u4e3a\u653b\u51fb\u884c\u4e3a\uff0c"</code> |
| L0012 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "\u5982\u662f\u8bf7\u7ed9\u51fa\u653b\u51fb\u7c7b\u578b\u3001\u5224\u5b9a\u4f9d\u636e\u3001"</code> |
| L0013 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "\u98ce\u9669\u7b49\u7ea7\u548c\u5904\u7f6e\u5efa\u8bae\u3002"</code> |
| L0014 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>)</code> |
| L0015 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0016 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0017 | 定义读取jsonl函数 &#96;read_jsonl&#96;，封装可复用业务逻辑。 | <code>def read_jsonl(path: Path, *, tolerate_invalid: bool = False):</code> |
| L0018 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 read_jsonl。 | <code>    if not path.exists():</code> |
| L0019 | 结束当前函数并把结果返回给调用方，当前位于函数 read_jsonl。 | <code>        return</code> |
| L0020 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 read_jsonl。 | <code>    with path.open("r", encoding="utf-8-sig") as f:</code> |
| L0021 | 遍历集合中的数据项并逐项处理，当前位于函数 read_jsonl。 | <code>        for line_no, line in enumerate(f, start=1):</code> |
| L0022 | 计算并保存 &#96;line&#96;（line），供后续逻辑使用，当前位于函数 read_jsonl。 | <code>            line = line.strip()</code> |
| L0023 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 read_jsonl。 | <code>            if line:</code> |
| L0024 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 read_jsonl。 | <code>                try:</code> |
| L0025 | 计算并保存 &#96;value&#96;（value），供后续逻辑使用，当前位于函数 read_jsonl。 | <code>                    value = json.loads(line)</code> |
| L0026 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 read_jsonl。 | <code>                except json.JSONDecodeError as exc:</code> |
| L0027 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 read_jsonl。 | <code>                    if tolerate_invalid:</code> |
| L0028 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 read_jsonl。 | <code>                        print(f"[WARN] skip invalid JSONL line: {path}:{line_no}: {exc}")</code> |
| L0029 | 控制当前循环或占位分支的执行流程，当前位于函数 read_jsonl。 | <code>                        continue</code> |
| L0030 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 read_jsonl。 | <code>                    raise</code> |
| L0031 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 read_jsonl。 | <code>                if not isinstance(value, dict):</code> |
| L0032 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 read_jsonl。 | <code>                    if tolerate_invalid:</code> |
| L0033 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 read_jsonl。 | <code>                        print(f"[WARN] skip non-object JSONL line: {path}:{line_no}")</code> |
| L0034 | 控制当前循环或占位分支的执行流程，当前位于函数 read_jsonl。 | <code>                        continue</code> |
| L0035 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 read_jsonl。 | <code>                    raise ValueError(f"JSONL record must be an object: {path}:{line_no}")</code> |
| L0036 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 read_jsonl。 | <code>                yield value</code> |
| L0037 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0038 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0039 | 定义写入jsonlappend函数 &#96;write_jsonl_append&#96;，封装可复用业务逻辑。 | <code>def write_jsonl_append(path: Path, records):</code> |
| L0040 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_jsonl_append。 | <code>    path.parent.mkdir(parents=True, exist_ok=True)</code> |
| L0041 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 write_jsonl_append。 | <code>    with path.open("a", encoding="utf-8") as f:</code> |
| L0042 | 遍历集合中的数据项并逐项处理，当前位于函数 write_jsonl_append。 | <code>        for record in records:</code> |
| L0043 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_jsonl_append。 | <code>            f.write(json.dumps(record, ensure_ascii=False) + "\n")</code> |
| L0044 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0045 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0046 | 定义写入jsonl函数 &#96;write_jsonl&#96;，封装可复用业务逻辑。 | <code>def write_jsonl(path: Path, records):</code> |
| L0047 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_jsonl。 | <code>    path.parent.mkdir(parents=True, exist_ok=True)</code> |
| L0048 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 write_jsonl。 | <code>    with path.open("w", encoding="utf-8") as f:</code> |
| L0049 | 遍历集合中的数据项并逐项处理，当前位于函数 write_jsonl。 | <code>        for record in records:</code> |
| L0050 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_jsonl。 | <code>            f.write(json.dumps(record, ensure_ascii=False) + "\n")</code> |
| L0051 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0052 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0053 | 定义加载manifest函数 &#96;load_manifest&#96;，封装可复用业务逻辑。 | <code>def load_manifest(manifest_path: Path):</code> |
| L0054 | 源码原注释：A disk-full interruption can leave a partial final line. Keep valid history | <code>    # A disk-full interruption can leave a partial final line. Keep valid history</code> |
| L0055 | 源码原注释：available and rewrite the manifest after this export instead of blocking all | <code>    # available and rewrite the manifest after this export instead of blocking all</code> |
| L0056 | 源码原注释：subsequent traffic forever. | <code>    # subsequent traffic forever.</code> |
| L0057 | 计算并保存 &#96;records&#96;（records），供后续逻辑使用，当前位于函数 load_manifest。 | <code>    records = list(read_jsonl(manifest_path, tolerate_invalid=True)) if manifest_path.exists() else []</code> |
| L0058 | 计算并保存 &#96;existing_keys&#96;（existingkeys），供后续逻辑使用，当前位于函数 load_manifest。 | <code>    existing_keys = set()</code> |
| L0059 | 计算并保存 &#96;key_to_idx&#96;（keytoidx），供后续逻辑使用，当前位于函数 load_manifest。 | <code>    key_to_idx = {}</code> |
| L0060 | 计算并保存 &#96;max_case_num&#96;（maxcasenum），供后续逻辑使用，当前位于函数 load_manifest。 | <code>    max_case_num = 0</code> |
| L0061 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0062 | 遍历集合中的数据项并逐项处理，当前位于函数 load_manifest。 | <code>    for idx, r in enumerate(records):</code> |
| L0063 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 load_manifest。 | <code>        try:</code> |
| L0064 | 计算并保存 &#96;key&#96;（key），供后续逻辑使用，当前位于函数 load_manifest。 | <code>            key = (str(r.get("file_id")), int(r.get("seq_id")))</code> |
| L0065 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 load_manifest。 | <code>            existing_keys.add(key)</code> |
| L0066 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_manifest。 | <code>            key_to_idx[key] = idx</code> |
| L0067 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 load_manifest。 | <code>        except Exception:</code> |
| L0068 | 控制当前循环或占位分支的执行流程，当前位于函数 load_manifest。 | <code>            pass</code> |
| L0069 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0070 | 计算并保存 &#96;case_id&#96;（caseid），供后续逻辑使用，当前位于函数 load_manifest。 | <code>        case_id = str(r.get("case_id", ""))</code> |
| L0071 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 load_manifest。 | <code>        if case_id.startswith("b."):</code> |
| L0072 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 load_manifest。 | <code>            try:</code> |
| L0073 | 计算并保存 &#96;num&#96;（num），供后续逻辑使用，当前位于函数 load_manifest。 | <code>                num = int(case_id.split(".", 1)[1])</code> |
| L0074 | 计算并保存 &#96;max_case_num&#96;（maxcasenum），供后续逻辑使用，当前位于函数 load_manifest。 | <code>                max_case_num = max(max_case_num, num)</code> |
| L0075 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 load_manifest。 | <code>            except Exception:</code> |
| L0076 | 控制当前循环或占位分支的执行流程，当前位于函数 load_manifest。 | <code>                pass</code> |
| L0077 | 结束当前函数并把结果返回给调用方，当前位于函数 load_manifest。 | <code>    return records, existing_keys, key_to_idx, max_case_num</code> |
| L0078 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0079 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0080 | 定义ensuretext函数 &#96;ensure_text&#96;，封装可复用业务逻辑。 | <code>def ensure_text(path: Path, text: str):</code> |
| L0081 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ensure_text。 | <code>    path.write_text(text or "", encoding="utf-8")</code> |
| L0082 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0083 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0084 | 定义读取candidatescore函数 &#96;get_candidate_score&#96;，封装可复用业务逻辑。 | <code>def get_candidate_score(cand: dict) -&gt; float:</code> |
| L0085 | 遍历集合中的数据项并逐项处理，当前位于函数 get_candidate_score。 | <code>    for key in ("raw_score", "score", "norm_score"):</code> |
| L0086 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 get_candidate_score。 | <code>        try:</code> |
| L0087 | 计算并保存 &#96;value&#96;（value），供后续逻辑使用，当前位于函数 get_candidate_score。 | <code>            value = cand.get(key)</code> |
| L0088 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 get_candidate_score。 | <code>            if value is None:</code> |
| L0089 | 控制当前循环或占位分支的执行流程，当前位于函数 get_candidate_score。 | <code>                continue</code> |
| L0090 | 结束当前函数并把结果返回给调用方，当前位于函数 get_candidate_score。 | <code>            return float(value)</code> |
| L0091 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 get_candidate_score。 | <code>        except Exception:</code> |
| L0092 | 控制当前循环或占位分支的执行流程，当前位于函数 get_candidate_score。 | <code>            continue</code> |
| L0093 | 结束当前函数并把结果返回给调用方，当前位于函数 get_candidate_score。 | <code>    return 0.0</code> |
| L0094 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0095 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0096 | 定义infer攻击type函数 &#96;infer_attack_type&#96;，封装可复用业务逻辑。 | <code>def infer_attack_type(cand: dict) -&gt; str:</code> |
| L0097 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 infer_attack_type。 | <code>    if cand.get("attack_type"):</code> |
| L0098 | 结束当前函数并把结果返回给调用方，当前位于函数 infer_attack_type。 | <code>        return str(cand.get("attack_type"))</code> |
| L0099 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0100 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 infer_attack_type。 | <code>    text = "\n".join(</code> |
| L0101 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 infer_attack_type。 | <code>        [</code> |
| L0102 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 infer_attack_type。 | <code>            str(cand.get("uri") or ""),</code> |
| L0103 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 infer_attack_type。 | <code>            str(cand.get("request_text") or ""),</code> |
| L0104 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 infer_attack_type。 | <code>            str(cand.get("raw_request_block") or ""),</code> |
| L0105 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 infer_attack_type。 | <code>        ]</code> |
| L0106 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 infer_attack_type。 | <code>    ).lower()</code> |
| L0107 | 计算并保存 &#96;rules&#96;（rules），供后续逻辑使用，当前位于函数 infer_attack_type。 | <code>    rules = [</code> |
| L0108 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 infer_attack_type。 | <code>        (</code> |
| L0109 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 infer_attack_type。 | <code>            r"(?:\bor\b\s+1=1&#124;union\s+select&#124;information_schema&#124;sleep\(&#124;benchmark\(&#124;ascii\s*\(&#124;substr\s*\(&#124;database\s*\(&#124;\band\b.+--&#124;'\s*or\s*'?\d)",</code> |
| L0110 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 infer_attack_type。 | <code>            "\u0053\u0051\u004c\u6ce8\u5165",</code> |
| L0111 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 infer_attack_type。 | <code>        ),</code> |
| L0112 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 infer_attack_type。 | <code>        (r"(&lt;script&#124;javascript:&#124;onerror=&#124;onload=)", "XSS"),</code> |
| L0113 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 infer_attack_type。 | <code>        (r"(\.\./&#124;\.\.\\&#124;/etc/passwd&#124;\\windows\\system32)", "\u8def\u5f84\u904d\u5386"),</code> |
| L0114 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 infer_attack_type。 | <code>        (r"(cmd\.exe&#124;/bin/sh&#124;powershell&#124;;\s*cat\s+)", "\u547d\u4ee4\u6ce8\u5165"),</code> |
| L0115 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 infer_attack_type。 | <code>        (r"(multipart/form-data&#124;\.php&#124;\.jsp&#124;\.aspx)", "\u6587\u4ef6\u4e0a\u4f20"),</code> |
| L0116 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 infer_attack_type。 | <code>        (r"(scan&#124;masscan&#124;nmap)", "\u7aef\u53e3\u626b\u63cf"),</code> |
| L0117 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 infer_attack_type。 | <code>    ]</code> |
| L0118 | 遍历集合中的数据项并逐项处理，当前位于函数 infer_attack_type。 | <code>    for pattern, label in rules:</code> |
| L0119 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 infer_attack_type。 | <code>        if re.search(pattern, text, re.I):</code> |
| L0120 | 结束当前函数并把结果返回给调用方，当前位于函数 infer_attack_type。 | <code>            return label</code> |
| L0121 | 结束当前函数并把结果返回给调用方，当前位于函数 infer_attack_type。 | <code>    return "\u53ef\u7591\u6d41\u91cf"</code> |
| L0122 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0123 | 定义main函数 &#96;main&#96;，封装可复用业务逻辑。 | <code>def main():</code> |
| L0124 | 计算并保存 &#96;parser&#96;（parser），供后续逻辑使用，当前位于函数 main。 | <code>    parser = argparse.ArgumentParser(description="Export demo_candidates into result cases.")</code> |
| L0125 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--input", required=True, help="Path to demo_candidates.jsonl.")</code> |
| L0126 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--result-dir", default="result", help="Result root directory.")</code> |
| L0127 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--min-score", type=float, default=0.3, help="Minimum export score based on raw_score/score.")</code> |
| L0128 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument(</code> |
| L0129 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "--plain-auth-min-score",</code> |
| L0130 | 计算并保存 &#96;type&#96;（type），供后续逻辑使用，当前位于函数 main。 | <code>        type=float,</code> |
| L0131 | 计算并保存 &#96;default&#96;（default），供后续逻辑使用，当前位于函数 main。 | <code>        default=0.88,</code> |
| L0132 | 计算并保存 &#96;help&#96;（help），供后续逻辑使用，当前位于函数 main。 | <code>        help="Extra export threshold for one-off ordinary login attempts without attack signals.",</code> |
| L0133 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>    )</code> |
| L0134 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--update-existing", action="store_true", help="Overwrite an existing case with the same file_id and seq_id.")</code> |
| L0135 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument(</code> |
| L0136 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "--enable-v2-gate",</code> |
| L0137 | 计算并保存 &#96;action&#96;（action），供后续逻辑使用，当前位于函数 main。 | <code>        action="store_true",</code> |
| L0138 | 计算并保存 &#96;help&#96;（help），供后续逻辑使用，当前位于函数 main。 | <code>        help="Use v2 payload/POC/behavior fusion gate before exporting to result.",</code> |
| L0139 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>    )</code> |
| L0140 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--v2-model-path", default="models/payload_model_v2.joblib", help="v2 payload model path.")</code> |
| L0141 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--v2-rules-path", default="rules/poc_rules.json", help="v2 POC rules path.")</code> |
| L0142 | 计算并保存 &#96;args&#96;（args），供后续逻辑使用，当前位于函数 main。 | <code>    args = parser.parse_args()</code> |
| L0143 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0144 | 计算并保存 &#96;input_path&#96;（inputpath），供后续逻辑使用，当前位于函数 main。 | <code>    input_path = Path(args.input)</code> |
| L0145 | 计算并保存 &#96;result_dir&#96;（结果dir），供后续逻辑使用，当前位于函数 main。 | <code>    result_dir = Path(args.result_dir)</code> |
| L0146 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    result_dir.mkdir(parents=True, exist_ok=True)</code> |
| L0147 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0148 | 计算并保存 &#96;manifest_path&#96;（manifestpath），供后续逻辑使用，当前位于函数 main。 | <code>    manifest_path = result_dir / "manifest.jsonl"</code> |
| L0149 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0150 | 计算并保存 &#96;candidates&#96;（candidates），供后续逻辑使用，当前位于函数 main。 | <code>    candidates = list(read_jsonl(input_path))</code> |
| L0151 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    manifest_records, existing_keys, key_to_idx, max_case_num = load_manifest(manifest_path)</code> |
| L0152 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0153 | 计算并保存 &#96;exported&#96;（exported），供后续逻辑使用，当前位于函数 main。 | <code>    exported = []</code> |
| L0154 | 计算并保存 &#96;skipped&#96;（skipped），供后续逻辑使用，当前位于函数 main。 | <code>    skipped = 0</code> |
| L0155 | 计算并保存 &#96;filtered_low_score&#96;（filteredlowscore），供后续逻辑使用，当前位于函数 main。 | <code>    filtered_low_score = 0</code> |
| L0156 | 计算并保存 &#96;filtered_plain_auth&#96;（filteredplainauth），供后续逻辑使用，当前位于函数 main。 | <code>    filtered_plain_auth = 0</code> |
| L0157 | 计算并保存 &#96;filtered_v2_raw&#96;（filteredv2raw），供后续逻辑使用，当前位于函数 main。 | <code>    filtered_v2_raw = 0</code> |
| L0158 | 计算并保存 &#96;v2_candidate_count&#96;（v2candidatecount），供后续逻辑使用，当前位于函数 main。 | <code>    v2_candidate_count = 0</code> |
| L0159 | 计算并保存 &#96;v2_attack_event_count&#96;（v2攻击事件count），供后续逻辑使用，当前位于函数 main。 | <code>    v2_attack_event_count = 0</code> |
| L0160 | 计算并保存 &#96;updated_existing&#96;（updatedexisting），供后续逻辑使用，当前位于函数 main。 | <code>    updated_existing = 0</code> |
| L0161 | 计算并保存 &#96;updated_case_ids&#96;（updatedcaseids），供后续逻辑使用，当前位于函数 main。 | <code>    updated_case_ids = []</code> |
| L0162 | 计算并保存 &#96;new_case_ids&#96;（newcaseids），供后续逻辑使用，当前位于函数 main。 | <code>    new_case_ids = []</code> |
| L0163 | 计算并保存 &#96;next_case_num&#96;（nextcasenum），供后续逻辑使用，当前位于函数 main。 | <code>    next_case_num = max_case_num + 1</code> |
| L0164 | 计算并保存 &#96;v2_engine&#96;（v2engine），供后续逻辑使用，当前位于函数 main。 | <code>    v2_engine = None</code> |
| L0165 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>    if args.enable_v2_gate:</code> |
| L0166 | 计算并保存 &#96;project_root&#96;（projectroot），供后续逻辑使用，当前位于函数 main。 | <code>        project_root = Path(__file__).resolve().parent.parent</code> |
| L0167 | 计算并保存 &#96;v2_engine&#96;（v2engine），供后续逻辑使用，当前位于函数 main。 | <code>        v2_engine = DetectionEngineV2(</code> |
| L0168 | 计算并保存 &#96;model_path&#96;（模型path），供后续逻辑使用，当前位于函数 main。 | <code>            model_path=(project_root / args.v2_model_path).resolve(),</code> |
| L0169 | 计算并保存 &#96;rules_path&#96;（rulespath），供后续逻辑使用，当前位于函数 main。 | <code>            rules_path=(project_root / args.v2_rules_path).resolve(),</code> |
| L0170 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>        )</code> |
| L0171 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0172 | 遍历集合中的数据项并逐项处理，当前位于函数 main。 | <code>    for cand in candidates:</code> |
| L0173 | 计算并保存 &#96;signal&#96;（signal），供后续逻辑使用，当前位于函数 main。 | <code>        signal = detect_request_attack(cand)</code> |
| L0174 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>        if signal:</code> |
| L0175 | 计算并保存 &#96;cand&#96;（cand），供后续逻辑使用，当前位于函数 main。 | <code>            cand = apply_rule_signal(cand, signal)</code> |
| L0176 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0177 | 计算并保存 &#96;v2_detection&#96;（v2detection），供后续逻辑使用，当前位于函数 main。 | <code>        v2_detection = None</code> |
| L0178 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>        if v2_engine is not None:</code> |
| L0179 | 计算并保存 &#96;v2_detection&#96;（v2detection），供后续逻辑使用，当前位于函数 main。 | <code>            v2_detection = v2_engine.detect(cand)</code> |
| L0180 | 计算并保存 &#96;fusion&#96;（fusion），供后续逻辑使用，当前位于函数 main。 | <code>            fusion = v2_detection.get("fusion") or {}</code> |
| L0181 | 计算并保存 &#96;decision&#96;（decision），供后续逻辑使用，当前位于函数 main。 | <code>            decision = str(fusion.get("decision") or "")</code> |
| L0182 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>            if decision == "raw_only":</code> |
| L0183 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                filtered_v2_raw += 1</code> |
| L0184 | 控制当前循环或占位分支的执行流程，当前位于函数 main。 | <code>                continue</code> |
| L0185 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>            if decision == "candidate":</code> |
| L0186 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                v2_candidate_count += 1</code> |
| L0187 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>            if decision == "attack_event":</code> |
| L0188 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                v2_attack_event_count += 1</code> |
| L0189 | 计算并保存 &#96;cand&#96;（cand），供后续逻辑使用，当前位于函数 main。 | <code>            cand = dict(cand)</code> |
| L0190 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            cand["v2_decision"] = decision</code> |
| L0191 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            cand["v2_final_score"] = fusion.get("final_score")</code> |
| L0192 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            cand["v2_risk_level"] = fusion.get("risk_level")</code> |
| L0193 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            cand["v2_payload_label"] = fusion.get("payload_label")</code> |
| L0194 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            cand["v2_payload_score"] = fusion.get("payload_score")</code> |
| L0195 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            cand["v2_behavior_type"] = fusion.get("behavior_type")</code> |
| L0196 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            cand["v2_behavior_score"] = fusion.get("behavior_score")</code> |
| L0197 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            cand["v2_poc_score"] = fusion.get("poc_score")</code> |
| L0198 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            cand["v2_evidence"] = fusion.get("evidence") or []</code> |
| L0199 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            cand["v2_poc_matches"] = fusion.get("poc_matches") or []</code> |
| L0200 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>            if fusion.get("attack_type"):</code> |
| L0201 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                cand["attack_type"] = fusion.get("attack_type")</code> |
| L0202 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>            if fusion.get("final_score") is not None:</code> |
| L0203 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                cand["raw_score"] = max(get_candidate_score(cand), float(fusion.get("final_score") or 0.0))</code> |
| L0204 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            cand["detection_source"] = "v2_fusion"</code> |
| L0205 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0206 | 计算并保存 &#96;score_value&#96;（scorevalue），供后续逻辑使用，当前位于函数 main。 | <code>        score_value = get_candidate_score(cand)</code> |
| L0207 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>        if not signal and is_plain_auth_attempt(cand) and score_value &lt; args.plain_auth_min_score:</code> |
| L0208 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            filtered_plain_auth += 1</code> |
| L0209 | 控制当前循环或占位分支的执行流程，当前位于函数 main。 | <code>            continue</code> |
| L0210 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0211 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>        if score_value &lt; args.min_score:</code> |
| L0212 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            filtered_low_score += 1</code> |
| L0213 | 控制当前循环或占位分支的执行流程，当前位于函数 main。 | <code>            continue</code> |
| L0214 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0215 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 main。 | <code>        try:</code> |
| L0216 | 计算并保存 &#96;file_id&#96;（fileid），供后续逻辑使用，当前位于函数 main。 | <code>            file_id = str(cand.get("file_id"))</code> |
| L0217 | 计算并保存 &#96;seq_id&#96;（seqid），供后续逻辑使用，当前位于函数 main。 | <code>            seq_id = int(cand.get("seq_id"))</code> |
| L0218 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 main。 | <code>        except Exception:</code> |
| L0219 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            skipped += 1</code> |
| L0220 | 控制当前循环或占位分支的执行流程，当前位于函数 main。 | <code>            continue</code> |
| L0221 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0222 | 计算并保存 &#96;key&#96;（key），供后续逻辑使用，当前位于函数 main。 | <code>        key = (file_id, seq_id)</code> |
| L0223 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>        if key in existing_keys:</code> |
| L0224 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>            if not args.update_existing:</code> |
| L0225 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                skipped += 1</code> |
| L0226 | 控制当前循环或占位分支的执行流程，当前位于函数 main。 | <code>                continue</code> |
| L0227 | 计算并保存 &#96;idx&#96;（idx），供后续逻辑使用，当前位于函数 main。 | <code>            idx = key_to_idx.get(key)</code> |
| L0228 | 计算并保存 &#96;existing_row&#96;（existingrow），供后续逻辑使用，当前位于函数 main。 | <code>            existing_row = manifest_records[idx] if idx is not None else {}</code> |
| L0229 | 计算并保存 &#96;case_id&#96;（caseid），供后续逻辑使用，当前位于函数 main。 | <code>            case_id = str(existing_row.get("case_id", ""))</code> |
| L0230 | 计算并保存 &#96;case_dir_from_manifest&#96;（casedirfrommanifest），供后续逻辑使用，当前位于函数 main。 | <code>            case_dir_from_manifest = str(existing_row.get("case_dir", "")).strip()</code> |
| L0231 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>            if case_dir_from_manifest:</code> |
| L0232 | 计算并保存 &#96;case_dir&#96;（casedir），供后续逻辑使用，当前位于函数 main。 | <code>                case_dir = Path(case_dir_from_manifest)</code> |
| L0233 | 当前一条件未命中时继续判断另一条件，当前位于函数 main。 | <code>            elif case_id:</code> |
| L0234 | 计算并保存 &#96;case_dir&#96;（casedir），供后续逻辑使用，当前位于函数 main。 | <code>                case_dir = result_dir / case_id</code> |
| L0235 | 处理前述条件均未命中的情况，当前位于函数 main。 | <code>            else:</code> |
| L0236 | 计算并保存 &#96;case_id&#96;（caseid），供后续逻辑使用，当前位于函数 main。 | <code>                case_id = f"b.{next_case_num}"</code> |
| L0237 | 计算并保存 &#96;case_dir&#96;（casedir），供后续逻辑使用，当前位于函数 main。 | <code>                case_dir = result_dir / case_id</code> |
| L0238 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                next_case_num += 1</code> |
| L0239 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            case_dir.mkdir(parents=True, exist_ok=True)</code> |
| L0240 | 计算并保存 &#96;is_update&#96;（is更新），供后续逻辑使用，当前位于函数 main。 | <code>            is_update = True</code> |
| L0241 | 处理前述条件均未命中的情况，当前位于函数 main。 | <code>        else:</code> |
| L0242 | 计算并保存 &#96;case_id&#96;（caseid），供后续逻辑使用，当前位于函数 main。 | <code>            case_id = f"b.{next_case_num}"</code> |
| L0243 | 计算并保存 &#96;case_dir&#96;（casedir），供后续逻辑使用，当前位于函数 main。 | <code>            case_dir = result_dir / case_id</code> |
| L0244 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            case_dir.mkdir(parents=True, exist_ok=True)</code> |
| L0245 | 计算并保存 &#96;is_update&#96;（is更新），供后续逻辑使用，当前位于函数 main。 | <code>            is_update = False</code> |
| L0246 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0247 | 计算并保存 &#96;export_time&#96;（exporttime），供后续逻辑使用，当前位于函数 main。 | <code>        export_time = datetime.now().isoformat(timespec="seconds")</code> |
| L0248 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0249 | 计算并保存 &#96;case_json&#96;（casejson），供后续逻辑使用，当前位于函数 main。 | <code>        case_json = {</code> |
| L0250 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "case_id": case_id,</code> |
| L0251 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "file_id": file_id,</code> |
| L0252 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "seq_id": seq_id,</code> |
| L0253 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "rank": cand.get("rank"),</code> |
| L0254 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "raw_score": cand.get("raw_score"),</code> |
| L0255 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "original_model_score": cand.get("original_model_score"),</code> |
| L0256 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "norm_score": cand.get("norm_score"),</code> |
| L0257 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "label": cand.get("label"),</code> |
| L0258 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "model_name": cand.get("model_name"),</code> |
| L0259 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "detection_source": cand.get("detection_source") or "model",</code> |
| L0260 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "rule_score": cand.get("rule_score"),</code> |
| L0261 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "rule_reason": cand.get("rule_reason"),</code> |
| L0262 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "v2_decision": cand.get("v2_decision"),</code> |
| L0263 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "v2_final_score": cand.get("v2_final_score"),</code> |
| L0264 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "v2_risk_level": cand.get("v2_risk_level"),</code> |
| L0265 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "v2_payload_label": cand.get("v2_payload_label"),</code> |
| L0266 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "v2_payload_score": cand.get("v2_payload_score"),</code> |
| L0267 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "v2_behavior_type": cand.get("v2_behavior_type"),</code> |
| L0268 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "v2_behavior_score": cand.get("v2_behavior_score"),</code> |
| L0269 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "v2_poc_score": cand.get("v2_poc_score"),</code> |
| L0270 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "v2_evidence": cand.get("v2_evidence"),</code> |
| L0271 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "v2_poc_matches": cand.get("v2_poc_matches"),</code> |
| L0272 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "source_ip": cand.get("source_ip"),</code> |
| L0273 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "destination_ip": cand.get("destination_ip"),</code> |
| L0274 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "source_port": cand.get("source_port"),</code> |
| L0275 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "destination_port": cand.get("destination_port"),</code> |
| L0276 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "method": cand.get("method"),</code> |
| L0277 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "uri": cand.get("uri"),</code> |
| L0278 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "host": cand.get("host"),</code> |
| L0279 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "status_code": cand.get("status_code"),</code> |
| L0280 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "request_text": cand.get("request_text"),</code> |
| L0281 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "attack_type": infer_attack_type(cand),</code> |
| L0282 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "llm_task": cand.get("llm_task") or DEFAULT_LLM_TASK,</code> |
| L0283 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "export_time": export_time,</code> |
| L0284 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "status": "pending",</code> |
| L0285 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "llm_status": "pending",</code> |
| L0286 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>        }</code> |
| L0287 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0288 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        ensure_text(case_dir / "request.txt", cand.get("raw_request_block", ""))</code> |
| L0289 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        ensure_text(case_dir / "response.txt", cand.get("raw_response_block", ""))</code> |
| L0290 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        ensure_text(case_dir / "case.json", json.dumps(case_json, ensure_ascii=False, indent=2))</code> |
| L0291 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0292 | 计算并保存 &#96;manifest_row&#96;（manifestrow），供后续逻辑使用，当前位于函数 main。 | <code>        manifest_row = {</code> |
| L0293 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "case_id": case_id,</code> |
| L0294 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "file_id": file_id,</code> |
| L0295 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "seq_id": seq_id,</code> |
| L0296 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "source_ip": cand.get("source_ip"),</code> |
| L0297 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "destination_ip": cand.get("destination_ip"),</code> |
| L0298 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "uri": cand.get("uri"),</code> |
| L0299 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "raw_score": cand.get("raw_score"),</code> |
| L0300 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "original_model_score": cand.get("original_model_score"),</code> |
| L0301 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "norm_score": cand.get("norm_score"),</code> |
| L0302 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "label": cand.get("label"),</code> |
| L0303 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "attack_type": cand.get("attack_type") or infer_attack_type(cand),</code> |
| L0304 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "detection_source": cand.get("detection_source") or "model",</code> |
| L0305 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "v2_decision": cand.get("v2_decision"),</code> |
| L0306 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "v2_final_score": cand.get("v2_final_score"),</code> |
| L0307 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "v2_risk_level": cand.get("v2_risk_level"),</code> |
| L0308 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "status": "pending",</code> |
| L0309 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "case_dir": str(case_dir.resolve()).replace("\\", "/"),</code> |
| L0310 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>        }</code> |
| L0311 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0312 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>        if is_update:</code> |
| L0313 | 计算并保存 &#96;idx&#96;（idx），供后续逻辑使用，当前位于函数 main。 | <code>            idx = key_to_idx.get(key)</code> |
| L0314 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>            if idx is not None:</code> |
| L0315 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                manifest_records[idx] = manifest_row</code> |
| L0316 | 处理前述条件均未命中的情况，当前位于函数 main。 | <code>            else:</code> |
| L0317 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 main。 | <code>                manifest_records.append(manifest_row)</code> |
| L0318 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                key_to_idx[key] = len(manifest_records) - 1</code> |
| L0319 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            updated_existing += 1</code> |
| L0320 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 main。 | <code>            updated_case_ids.append(case_id)</code> |
| L0321 | 处理前述条件均未命中的情况，当前位于函数 main。 | <code>        else:</code> |
| L0322 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 main。 | <code>            manifest_records.append(manifest_row)</code> |
| L0323 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            key_to_idx[key] = len(manifest_records) - 1</code> |
| L0324 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 main。 | <code>            existing_keys.add(key)</code> |
| L0325 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 main。 | <code>            exported.append(manifest_row)</code> |
| L0326 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 main。 | <code>            new_case_ids.append(case_id)</code> |
| L0327 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            next_case_num += 1</code> |
| L0328 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0329 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>    if exported or updated_existing:</code> |
| L0330 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        write_jsonl(manifest_path, manifest_records)</code> |
| L0331 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0332 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print("=" * 80)</code> |
| L0333 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print("input candidates:", len(candidates))</code> |
| L0334 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print("low-score filtered:", filtered_low_score)</code> |
| L0335 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print("plain auth false-positive guard filtered:", filtered_plain_auth)</code> |
| L0336 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print("v2 raw-only filtered:", filtered_v2_raw)</code> |
| L0337 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print("v2 candidate exported:", v2_candidate_count)</code> |
| L0338 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print("v2 attack-event exported:", v2_attack_event_count)</code> |
| L0339 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print("existing/skipped:", skipped)</code> |
| L0340 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print("new exported:", len(exported))</code> |
| L0341 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print("updated existing:", updated_existing)</code> |
| L0342 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print("export min score:", args.min_score)</code> |
| L0343 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print("plain auth extra threshold:", args.plain_auth_min_score)</code> |
| L0344 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print("result dir:", result_dir.resolve())</code> |
| L0345 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print("new case_id list:", new_case_ids if new_case_ids else "none")</code> |
| L0346 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print("updated case_id list:", updated_case_ids if updated_case_ids else "none")</code> |
| L0347 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print("manifest path:", manifest_path.resolve())</code> |
| L0348 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print("=" * 80)</code> |
| L0349 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0350 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0351 | 判断条件是否成立，成立时进入对应处理分支。 | <code>if __name__ == "__main__":</code> |
| L0352 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    main()</code> |
