# `scripts/build_demo_candidates.py` 逐行注释

**脚本用途：** 辅助脚本：根据文件名 `build_demo_candidates.py` 完成对应的数据处理或运维任务。

**源码行数：** 133　**函数/类数量：** 6

| 行号 | 中文说明 | 原始源码 |
|---:|---|---|
| L0001 | 导入后续逻辑所需的模块、类或函数：&#96;import argparse&#96;。 | <code>import argparse</code> |
| L0002 | 导入后续逻辑所需的模块、类或函数：&#96;import json&#96;。 | <code>import json</code> |
| L0003 | 导入后续逻辑所需的模块、类或函数：&#96;import logging&#96;。 | <code>import logging</code> |
| L0004 | 导入后续逻辑所需的模块、类或函数：&#96;from pathlib import Path&#96;。 | <code>from pathlib import Path</code> |
| L0005 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0006 | 导入后续逻辑所需的模块、类或函数：&#96;from web_attack_rules import apply_rule_signal, detect_request_attack&#96;。 | <code>from web_attack_rules import apply_rule_signal, detect_request_attack</code> |
| L0007 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0008 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")</code> |
| L0009 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0010 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0011 | 定义读取jsonl函数 &#96;read_jsonl&#96;，封装可复用业务逻辑。 | <code>def read_jsonl(path: Path):</code> |
| L0012 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 read_jsonl。 | <code>    with path.open("r", encoding="utf-8") as f:</code> |
| L0013 | 遍历集合中的数据项并逐项处理，当前位于函数 read_jsonl。 | <code>        for line in f:</code> |
| L0014 | 计算并保存 &#96;line&#96;（line），供后续逻辑使用，当前位于函数 read_jsonl。 | <code>            line = line.strip()</code> |
| L0015 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 read_jsonl。 | <code>            if not line:</code> |
| L0016 | 控制当前循环或占位分支的执行流程，当前位于函数 read_jsonl。 | <code>                continue</code> |
| L0017 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 read_jsonl。 | <code>            yield json.loads(line)</code> |
| L0018 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0019 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0020 | 定义写入jsonl函数 &#96;write_jsonl&#96;，封装可复用业务逻辑。 | <code>def write_jsonl(records, path: Path):</code> |
| L0021 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 write_jsonl。 | <code>    with path.open("w", encoding="utf-8") as f:</code> |
| L0022 | 遍历集合中的数据项并逐项处理，当前位于函数 write_jsonl。 | <code>        for r in records:</code> |
| L0023 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_jsonl。 | <code>            f.write(json.dumps(r, ensure_ascii=False) + "\n")</code> |
| L0024 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0025 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0026 | 定义makekey函数 &#96;make_key&#96;，封装可复用业务逻辑。 | <code>def make_key(record: dict):</code> |
| L0027 | 结束当前函数并把结果返回给调用方，当前位于函数 make_key。 | <code>    return str(record.get("file_id")), int(record.get("seq_id"))</code> |
| L0028 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0029 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0030 | 定义indexbykey函数 &#96;index_by_key&#96;，封装可复用业务逻辑。 | <code>def index_by_key(path: Path):</code> |
| L0031 | 计算并保存 &#96;mapping&#96;（mapping），供后续逻辑使用，当前位于函数 index_by_key。 | <code>    mapping = {}</code> |
| L0032 | 遍历集合中的数据项并逐项处理，当前位于函数 index_by_key。 | <code>    for rec in read_jsonl(path):</code> |
| L0033 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 index_by_key。 | <code>        try:</code> |
| L0034 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 index_by_key。 | <code>            mapping[make_key(rec)] = rec</code> |
| L0035 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 index_by_key。 | <code>        except Exception as exc:  # noqa: BLE001</code> |
| L0036 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 index_by_key。 | <code>            logging.warning("跳过异常记录: %s &#124; %s", exc, rec)</code> |
| L0037 | 结束当前函数并把结果返回给调用方，当前位于函数 index_by_key。 | <code>    return mapping</code> |
| L0038 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0039 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0040 | 定义构建candidate函数 &#96;build_candidate&#96;，封装可复用业务逻辑。 | <code>def build_candidate(item: dict, parsed_map: dict, input_map: dict) -&gt; dict:</code> |
| L0041 | 计算并保存 &#96;key&#96;（key），供后续逻辑使用，当前位于函数 build_candidate。 | <code>    key = make_key(item)</code> |
| L0042 | 计算并保存 &#96;parsed_rec&#96;（parsedrec），供后续逻辑使用，当前位于函数 build_candidate。 | <code>    parsed_rec = parsed_map.get(key, {})</code> |
| L0043 | 计算并保存 &#96;input_rec&#96;（inputrec），供后续逻辑使用，当前位于函数 build_candidate。 | <code>    input_rec = input_map.get(key, {})</code> |
| L0044 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0045 | 结束当前函数并把结果返回给调用方，当前位于函数 build_candidate。 | <code>    return {</code> |
| L0046 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_candidate。 | <code>        "file_id": key[0],</code> |
| L0047 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_candidate。 | <code>        "seq_id": key[1],</code> |
| L0048 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_candidate。 | <code>        "rank": item.get("rank"),</code> |
| L0049 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_candidate。 | <code>        "raw_score": item.get("raw_score", item.get("score")),</code> |
| L0050 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_candidate。 | <code>        "norm_score": item.get("norm_score"),</code> |
| L0051 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_candidate。 | <code>        "label": item.get("label"),</code> |
| L0052 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_candidate。 | <code>        "model_name": item.get("model_name"),</code> |
| L0053 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_candidate。 | <code>        "source_ip": parsed_rec.get("src_ip", input_rec.get("src_ip")),</code> |
| L0054 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_candidate。 | <code>        "destination_ip": parsed_rec.get("dst_ip", input_rec.get("dst_ip")),</code> |
| L0055 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_candidate。 | <code>        "source_port": parsed_rec.get("src_port", input_rec.get("src_port")),</code> |
| L0056 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_candidate。 | <code>        "destination_port": parsed_rec.get("dst_port", input_rec.get("dst_port")),</code> |
| L0057 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_candidate。 | <code>        "method": parsed_rec.get("method", input_rec.get("method")),</code> |
| L0058 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_candidate。 | <code>        "uri": parsed_rec.get("uri", input_rec.get("uri")),</code> |
| L0059 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_candidate。 | <code>        "host": parsed_rec.get("host", input_rec.get("host")),</code> |
| L0060 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_candidate。 | <code>        "status_code": parsed_rec.get("status_code", input_rec.get("status_code")),</code> |
| L0061 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_candidate。 | <code>        "request_text": input_rec.get("request_text"),</code> |
| L0062 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_candidate。 | <code>        "raw_request_block": parsed_rec.get("raw_request_block"),</code> |
| L0063 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_candidate。 | <code>        "raw_response_block": parsed_rec.get("raw_response_block"),</code> |
| L0064 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 build_candidate。 | <code>    }</code> |
| L0065 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0066 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0067 | 定义main函数 &#96;main&#96;，封装可复用业务逻辑。 | <code>def main():</code> |
| L0068 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 main。 | <code>    parser = argparse.ArgumentParser(description="根据 reranked 结果构建 demo 候选")</code> |
| L0069 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--parsed", required=True, help="parsed.jsonl")</code> |
| L0070 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--model-input", required=True, help="model_input.jsonl")</code> |
| L0071 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--reranked-result", required=True, help="reranked model_result.jsonl")</code> |
| L0072 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--output", required=True, help="demo_candidates.jsonl")</code> |
| L0073 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--top-k", type=int, default=3, help="选取前K条")</code> |
| L0074 | 计算并保存 &#96;args&#96;（args），供后续逻辑使用，当前位于函数 main。 | <code>    args = parser.parse_args()</code> |
| L0075 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0076 | 计算并保存 &#96;parsed_map&#96;（parsedmap），供后续逻辑使用，当前位于函数 main。 | <code>    parsed_map = index_by_key(Path(args.parsed))</code> |
| L0077 | 计算并保存 &#96;input_map&#96;（inputmap），供后续逻辑使用，当前位于函数 main。 | <code>    input_map = index_by_key(Path(args.model_input))</code> |
| L0078 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 main。 | <code>    reranked = list(read_jsonl(Path(args.reranked_result)))</code> |
| L0079 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 main。 | <code>    reranked.sort(key=lambda x: int(x.get("rank", 10**9)))</code> |
| L0080 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0081 | 计算并保存 &#96;candidates&#96;（candidates），供后续逻辑使用，当前位于函数 main。 | <code>    candidates = []</code> |
| L0082 | 计算并保存 &#96;selected_keys&#96;（selectedkeys），供后续逻辑使用，当前位于函数 main。 | <code>    selected_keys = set()</code> |
| L0083 | 计算并保存 &#96;top_k&#96;（topk），供后续逻辑使用，当前位于函数 main。 | <code>    top_k = max(args.top_k, 0)</code> |
| L0084 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0085 | 遍历集合中的数据项并逐项处理，当前位于函数 main。 | <code>    for idx, item in enumerate(reranked):</code> |
| L0086 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 main。 | <code>        try:</code> |
| L0087 | 计算并保存 &#96;candidate&#96;（candidate），供后续逻辑使用，当前位于函数 main。 | <code>            candidate = build_candidate(item, parsed_map, input_map)</code> |
| L0088 | 计算并保存 &#96;key&#96;（key），供后续逻辑使用，当前位于函数 main。 | <code>            key = (candidate["file_id"], candidate["seq_id"])</code> |
| L0089 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 main。 | <code>        except Exception:</code> |
| L0090 | 控制当前循环或占位分支的执行流程，当前位于函数 main。 | <code>            continue</code> |
| L0091 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0092 | 计算并保存 &#96;signal&#96;（signal），供后续逻辑使用，当前位于函数 main。 | <code>        signal = detect_request_attack(candidate)</code> |
| L0093 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>        if idx &gt;= top_k and not signal:</code> |
| L0094 | 控制当前循环或占位分支的执行流程，当前位于函数 main。 | <code>            continue</code> |
| L0095 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0096 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>        if signal:</code> |
| L0097 | 计算并保存 &#96;candidate&#96;（candidate），供后续逻辑使用，当前位于函数 main。 | <code>            candidate = apply_rule_signal(candidate, signal)</code> |
| L0098 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            logging.info(</code> |
| L0099 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                "rule hit: file_id=%s seq=%s type=%s score=%s",</code> |
| L0100 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                candidate.get("file_id"),</code> |
| L0101 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                candidate.get("seq_id"),</code> |
| L0102 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                candidate.get("attack_type"),</code> |
| L0103 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                candidate.get("raw_score"),</code> |
| L0104 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>            )</code> |
| L0105 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0106 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>        if key in selected_keys:</code> |
| L0107 | 控制当前循环或占位分支的执行流程，当前位于函数 main。 | <code>            continue</code> |
| L0108 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 main。 | <code>        selected_keys.add(key)</code> |
| L0109 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 main。 | <code>        candidates.append(candidate)</code> |
| L0110 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0111 | 计算并保存 &#96;output_path&#96;（outputpath），供后续逻辑使用，当前位于函数 main。 | <code>    output_path = Path(args.output)</code> |
| L0112 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    output_path.parent.mkdir(parents=True, exist_ok=True)</code> |
| L0113 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    write_jsonl(candidates, output_path)</code> |
| L0114 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0115 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    logging.info("parsed 记录数: %d", len(parsed_map))</code> |
| L0116 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    logging.info("model_input 记录数: %d", len(input_map))</code> |
| L0117 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 main。 | <code>    logging.info("reranked 记录数: %d", len(reranked))</code> |
| L0118 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    logging.info("top_k: %d", args.top_k)</code> |
| L0119 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    logging.info("demo_candidates 数量: %d", len(candidates))</code> |
| L0120 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    logging.info("输出文件: %s", output_path)</code> |
| L0121 | 遍历集合中的数据项并逐项处理，当前位于函数 main。 | <code>    for c in candidates[:5]:</code> |
| L0122 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        logging.info(</code> |
| L0123 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "rank=%s seq=%s raw_score=%s norm_score=%s uri=%s",</code> |
| L0124 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            c.get("rank"),</code> |
| L0125 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            c.get("seq_id"),</code> |
| L0126 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            c.get("raw_score"),</code> |
| L0127 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            c.get("norm_score"),</code> |
| L0128 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            c.get("uri"),</code> |
| L0129 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>        )</code> |
| L0130 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0131 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0132 | 判断条件是否成立，成立时进入对应处理分支。 | <code>if __name__ == "__main__":</code> |
| L0133 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    main()</code> |
