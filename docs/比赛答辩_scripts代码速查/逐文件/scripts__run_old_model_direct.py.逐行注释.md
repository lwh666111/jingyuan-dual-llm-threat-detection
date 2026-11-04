# `scripts/run_old_model_direct.py` 逐行注释

**脚本用途：** 辅助脚本：根据文件名 `run_old_model_direct.py` 完成对应的数据处理或运维任务。

**源码行数：** 145　**函数/类数量：** 7

| 行号 | 中文说明 | 原始源码 |
|---:|---|---|
| L0001 | 导入后续逻辑所需的模块、类或函数：&#96;import argparse&#96;。 | <code>import argparse</code> |
| L0002 | 导入后续逻辑所需的模块、类或函数：&#96;import csv&#96;。 | <code>import csv</code> |
| L0003 | 导入后续逻辑所需的模块、类或函数：&#96;import json&#96;。 | <code>import json</code> |
| L0004 | 导入后续逻辑所需的模块、类或函数：&#96;import logging&#96;。 | <code>import logging</code> |
| L0005 | 导入后续逻辑所需的模块、类或函数：&#96;from pathlib import Path&#96;。 | <code>from pathlib import Path</code> |
| L0006 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0007 | 导入后续逻辑所需的模块、类或函数：&#96;import joblib&#96;。 | <code>import joblib</code> |
| L0008 | 导入后续逻辑所需的模块、类或函数：&#96;import numpy as np&#96;。 | <code>import numpy as np</code> |
| L0009 | 导入后续逻辑所需的模块、类或函数：&#96;import pandas as pd&#96;。 | <code>import pandas as pd</code> |
| L0010 | 导入后续逻辑所需的模块、类或函数：&#96;import torch&#96;。 | <code>import torch</code> |
| L0011 | 导入后续逻辑所需的模块、类或函数：&#96;import torch.nn as nn&#96;。 | <code>import torch.nn as nn</code> |
| L0012 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0013 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")</code> |
| L0014 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0015 | 计算并保存 &#96;MODEL_NAME&#96;（模型NAME），供后续逻辑使用。 | <code>MODEL_NAME = "old_unsw_mlp_direct_compat_mode"</code> |
| L0016 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0017 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0018 | 定义类 &#96;MLP&#96;，集中保存相关状态与操作。 | <code>class MLP(nn.Module):</code> |
| L0019 | 定义init函数 &#96;__init__&#96;，封装可复用业务逻辑。 | <code>    def __init__(self, input_dim):</code> |
| L0020 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 __init__。 | <code>        super().__init__()</code> |
| L0021 | 计算并保存 &#96;net&#96;（net），供后续逻辑使用，当前位于函数 __init__。 | <code>        self.net = nn.Sequential(</code> |
| L0022 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 __init__。 | <code>            nn.Linear(input_dim, 256),</code> |
| L0023 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 __init__。 | <code>            nn.ReLU(),</code> |
| L0024 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 __init__。 | <code>            nn.Dropout(0.3),</code> |
| L0025 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 __init__。 | <code>            nn.Linear(256, 128),</code> |
| L0026 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 __init__。 | <code>            nn.ReLU(),</code> |
| L0027 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 __init__。 | <code>            nn.Dropout(0.3),</code> |
| L0028 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 __init__。 | <code>            nn.Linear(128, 64),</code> |
| L0029 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 __init__。 | <code>            nn.ReLU(),</code> |
| L0030 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 __init__。 | <code>            nn.Dropout(0.2),</code> |
| L0031 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 __init__。 | <code>            nn.Linear(64, 1),</code> |
| L0032 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 __init__。 | <code>        )</code> |
| L0033 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0034 | 定义forward函数 &#96;forward&#96;，封装可复用业务逻辑。 | <code>    def forward(self, x):</code> |
| L0035 | 结束当前函数并把结果返回给调用方，当前位于函数 forward。 | <code>        return self.net(x)</code> |
| L0036 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0037 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0038 | 定义加载requiredcols函数 &#96;load_required_cols&#96;，封装可复用业务逻辑。 | <code>def load_required_cols(preprocessor):</code> |
| L0039 | 计算并保存 &#96;numeric_cols&#96;（numericcols），供后续逻辑使用，当前位于函数 load_required_cols。 | <code>    numeric_cols = []</code> |
| L0040 | 计算并保存 &#96;categorical_cols&#96;（categoricalcols），供后续逻辑使用，当前位于函数 load_required_cols。 | <code>    categorical_cols = []</code> |
| L0041 | 遍历集合中的数据项并逐项处理，当前位于函数 load_required_cols。 | <code>    for name, transformer, cols in preprocessor.transformers_:</code> |
| L0042 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 load_required_cols。 | <code>        if name == "num":</code> |
| L0043 | 计算并保存 &#96;numeric_cols&#96;（numericcols），供后续逻辑使用，当前位于函数 load_required_cols。 | <code>            numeric_cols = list(cols)</code> |
| L0044 | 当前一条件未命中时继续判断另一条件，当前位于函数 load_required_cols。 | <code>        elif name == "cat":</code> |
| L0045 | 计算并保存 &#96;categorical_cols&#96;（categoricalcols），供后续逻辑使用，当前位于函数 load_required_cols。 | <code>            categorical_cols = list(cols)</code> |
| L0046 | 结束当前函数并把结果返回给调用方，当前位于函数 load_required_cols。 | <code>    return numeric_cols, categorical_cols</code> |
| L0047 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0048 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0049 | 定义写入jsonl函数 &#96;write_jsonl&#96;，封装可复用业务逻辑。 | <code>def write_jsonl(records, path: Path):</code> |
| L0050 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 write_jsonl。 | <code>    with path.open("w", encoding="utf-8") as f:</code> |
| L0051 | 遍历集合中的数据项并逐项处理，当前位于函数 write_jsonl。 | <code>        for record in records:</code> |
| L0052 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_jsonl。 | <code>            f.write(json.dumps(record, ensure_ascii=False) + "\n")</code> |
| L0053 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0054 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0055 | 定义写入csv函数 &#96;write_csv&#96;，封装可复用业务逻辑。 | <code>def write_csv(records, path: Path):</code> |
| L0056 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 write_csv。 | <code>    if not records:</code> |
| L0057 | 结束当前函数并把结果返回给调用方，当前位于函数 write_csv。 | <code>        return</code> |
| L0058 | 计算并保存 &#96;fieldnames&#96;（fieldnames），供后续逻辑使用，当前位于函数 write_csv。 | <code>    fieldnames = list(records[0].keys())</code> |
| L0059 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 write_csv。 | <code>    with path.open("w", encoding="utf-8-sig", newline="") as f:</code> |
| L0060 | 计算并保存 &#96;writer&#96;（writer），供后续逻辑使用，当前位于函数 write_csv。 | <code>        writer = csv.DictWriter(f, fieldnames=fieldnames)</code> |
| L0061 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_csv。 | <code>        writer.writeheader()</code> |
| L0062 | 遍历集合中的数据项并逐项处理，当前位于函数 write_csv。 | <code>        for r in records:</code> |
| L0063 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_csv。 | <code>            writer.writerow(r)</code> |
| L0064 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0065 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0066 | 定义main函数 &#96;main&#96;，封装可复用业务逻辑。 | <code>def main():</code> |
| L0067 | 计算并保存 &#96;parser&#96;（parser），供后续逻辑使用，当前位于函数 main。 | <code>    parser = argparse.ArgumentParser(description="鐩存帴杩愯鏃фā鍨?compatibility mode 鎺ㄧ悊")</code> |
| L0068 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--input", required=True, help="old_model_input.csv")</code> |
| L0069 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--preprocessor", required=True, help="preprocessor.joblib")</code> |
| L0070 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--model", required=True, help="best_mlp.pth")</code> |
| L0071 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--output-jsonl", required=True)</code> |
| L0072 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--output-csv", required=True)</code> |
| L0073 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--label-threshold", type=float, default=0.46)</code> |
| L0074 | 计算并保存 &#96;args&#96;（args），供后续逻辑使用，当前位于函数 main。 | <code>    args = parser.parse_args()</code> |
| L0075 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0076 | 计算并保存 &#96;df&#96;（df），供后续逻辑使用，当前位于函数 main。 | <code>    df = pd.read_csv(args.input)</code> |
| L0077 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    logging.info("杈撳叆璁板綍鏁? %d", len(df))</code> |
| L0078 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0079 | 计算并保存 &#96;preprocessor&#96;（preprocessor），供后续逻辑使用，当前位于函数 main。 | <code>    preprocessor = joblib.load(args.preprocessor)</code> |
| L0080 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    numeric_cols, categorical_cols = load_required_cols(preprocessor)</code> |
| L0081 | 计算并保存 &#96;required_cols&#96;（requiredcols），供后续逻辑使用，当前位于函数 main。 | <code>    required_cols = categorical_cols + numeric_cols</code> |
| L0082 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0083 | 计算并保存 &#96;missing&#96;（missing），供后续逻辑使用，当前位于函数 main。 | <code>    missing = [c for c in required_cols if c not in df.columns]</code> |
| L0084 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>    if missing:</code> |
| L0085 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 main。 | <code>        raise ValueError(f"杈撳叆缂哄皯鏃фā鍨嬮渶瑕佺殑鍒? {missing}")</code> |
| L0086 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0087 | 计算并保存 &#96;meta_df&#96;（metadf），供后续逻辑使用，当前位于函数 main。 | <code>    meta_df = df[["file_id", "seq_id"]].copy()</code> |
| L0088 | 计算并保存 &#96;feature_df&#96;（featuredf），供后续逻辑使用，当前位于函数 main。 | <code>    feature_df = df[required_cols].copy()</code> |
| L0089 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0090 | 计算并保存 &#96;X&#96;（X），供后续逻辑使用，当前位于函数 main。 | <code>    X = preprocessor.transform(feature_df)</code> |
| L0091 | 计算并保存 &#96;X&#96;（X），供后续逻辑使用，当前位于函数 main。 | <code>    X = X.toarray() if hasattr(X, "toarray") else X</code> |
| L0092 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    logging.info("鍙樻崲鍚庣煩闃?shape: %s", X.shape)</code> |
| L0093 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0094 | 计算并保存 &#96;device&#96;（device），供后续逻辑使用，当前位于函数 main。 | <code>    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")</code> |
| L0095 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0096 | 计算并保存 &#96;model&#96;（模型），供后续逻辑使用，当前位于函数 main。 | <code>    model = MLP(X.shape[1]).to(device)</code> |
| L0097 | 计算并保存 &#96;state_dict&#96;（statedict），供后续逻辑使用，当前位于函数 main。 | <code>    state_dict = torch.load(args.model, map_location=device)</code> |
| L0098 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    model.load_state_dict(state_dict)</code> |
| L0099 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    model.eval()</code> |
| L0100 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0101 | 计算并保存 &#96;X_tensor&#96;（Xtensor），供后续逻辑使用，当前位于函数 main。 | <code>    X_tensor = torch.tensor(X, dtype=torch.float32).to(device)</code> |
| L0102 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 main。 | <code>    with torch.no_grad():</code> |
| L0103 | 计算并保存 &#96;logits&#96;（logits），供后续逻辑使用，当前位于函数 main。 | <code>        logits = model(X_tensor)</code> |
| L0104 | 计算并保存 &#96;probs&#96;（probs），供后续逻辑使用，当前位于函数 main。 | <code>        probs = torch.sigmoid(logits).cpu().numpy().flatten()</code> |
| L0105 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0106 | 计算并保存 &#96;results&#96;（results），供后续逻辑使用，当前位于函数 main。 | <code>    results = []</code> |
| L0107 | 遍历集合中的数据项并逐项处理，当前位于函数 main。 | <code>    for idx, prob in enumerate(probs):</code> |
| L0108 | 计算并保存 &#96;label&#96;（label），供后续逻辑使用，当前位于函数 main。 | <code>        label = "suspicious" if prob &gt;= args.label_threshold else "benign"</code> |
| L0109 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 main。 | <code>        results.append(</code> |
| L0110 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            {</code> |
| L0111 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                "file_id": str(meta_df.iloc[idx]["file_id"]),</code> |
| L0112 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                "seq_id": int(meta_df.iloc[idx]["seq_id"]),</code> |
| L0113 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                "score": float(round(float(prob), 6)),</code> |
| L0114 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                "label": label,</code> |
| L0115 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                "model_name": MODEL_NAME,</code> |
| L0116 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>            }</code> |
| L0117 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>        )</code> |
| L0118 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0119 | 计算并保存 &#96;output_jsonl&#96;（outputjsonl），供后续逻辑使用，当前位于函数 main。 | <code>    output_jsonl = Path(args.output_jsonl)</code> |
| L0120 | 计算并保存 &#96;output_csv&#96;（outputcsv），供后续逻辑使用，当前位于函数 main。 | <code>    output_csv = Path(args.output_csv)</code> |
| L0121 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    output_jsonl.parent.mkdir(parents=True, exist_ok=True)</code> |
| L0122 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0123 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    write_jsonl(results, output_jsonl)</code> |
| L0124 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    write_csv(results, output_csv)</code> |
| L0125 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0126 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    logging.info("score 鏈€灏忓€? %.6f", float(np.min(probs)))</code> |
| L0127 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    logging.info("score 鏈€澶у€? %.6f", float(np.max(probs)))</code> |
| L0128 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    logging.info("score 骞冲潎鍊? %.6f", float(np.mean(probs)))</code> |
| L0129 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    logging.info("杈撳嚭 jsonl: %s", output_jsonl)</code> |
| L0130 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    logging.info("杈撳嚭 csv: %s", output_csv)</code> |
| L0131 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0132 | 遍历集合中的数据项并逐项处理，当前位于函数 main。 | <code>    for item in results[:5]:</code> |
| L0133 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        logging.info(</code> |
| L0134 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "seq=%s score=%s label=%s model=%s",</code> |
| L0135 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            item["seq_id"],</code> |
| L0136 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            item["score"],</code> |
| L0137 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            item["label"],</code> |
| L0138 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            item["model_name"],</code> |
| L0139 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>        )</code> |
| L0140 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0141 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0142 | 判断条件是否成立，成立时进入对应处理分支。 | <code>if __name__ == "__main__":</code> |
| L0143 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    main()</code> |
| L0144 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0145 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
