import argparse
import logging
from pathlib import Path

import joblib
import pandas as pd

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


def load_preprocessor_schema(preprocessor):
    numeric_cols = []
    categorical_cols = []
    categorical_choices = {}

    for name, transformer, cols in preprocessor.transformers_:
        if name == "num":
            numeric_cols = list(cols)
        elif name == "cat":
            categorical_cols = list(cols)
            onehot = None
            try:
                onehot = transformer.named_steps.get("onehot")
            except Exception:
                onehot = None

            if onehot is not None and hasattr(onehot, "categories_"):
                for col_name, cats in zip(categorical_cols, onehot.categories_):
                    categorical_choices[col_name] = [str(x) for x in cats]

    return numeric_cols, categorical_cols, categorical_choices


def choose_category(col_name, choices, row):
    cats = choices.get(col_name, [])

    if col_name == "proto":
        preferred = ["tcp", "udp", "icmp"]
    elif col_name == "service":
        preferred = ["http", "https", "-", "dns"]
    elif col_name == "state":
        if int(row.get("resp_is_error", 0)) == 1:
            preferred = ["INT", "FIN", "CON", "REQ"]
        else:
            preferred = ["FIN", "CON", "REQ", "INT"]
    else:
        preferred = []

    for item in preferred:
        if item in cats:
            return item

    if cats:
        return cats[0]

    fallback = {"proto": "tcp", "service": "http", "state": "FIN"}
    return fallback.get(col_name, "unknown")


def safe_num(row, key, default=0.0):
    try:
        value = row.get(key, default)
        if pd.isna(value):
            return float(default)
        return float(value)
    except Exception:
        return float(default)


def build_numeric_value(col, row):
    uri_len = safe_num(row, "uri_len")
    query_len = safe_num(row, "query_len")
    path_depth = safe_num(row, "path_depth")
    special_char_count = safe_num(row, "special_char_count")
    body_len = safe_num(row, "body_len")
    user_agent_len = safe_num(row, "user_agent_len")
    is_get = safe_num(row, "is_get")
    is_post = safe_num(row, "is_post")
    has_json_body = safe_num(row, "has_json_body")
    has_login_keyword = safe_num(row, "has_login_keyword")
    has_captcha_keyword = safe_num(row, "has_captcha_keyword")
    has_admin_keyword = safe_num(row, "has_admin_keyword")
    has_token_keyword = safe_num(row, "has_token_keyword")
    has_password_keyword = safe_num(row, "has_password_keyword")
    resp_is_error = safe_num(row, "resp_is_error")
    request_text_len = len(str(row.get("request_text", "") or ""))
    status_code = safe_num(row, "status_code", 200)

    dur = 0.05 + min(query_len, 2000) / 1000.0 + min(body_len, 10000) / 10000.0
    spkts = max(1.0, 1.0 + is_post + path_depth)
    dpkts = max(1.0, 1.0 + (1 if status_code > 0 else 0))
    sbytes = 120.0 + uri_len + body_len + user_agent_len
    dbytes = 80.0 + min(request_text_len, 5000) * 0.2
    rate = (spkts + dpkts) / max(dur, 0.001)
    sload = sbytes / max(dur, 0.001)
    dload = dbytes / max(dur, 0.001)
    sinpkt = dur / max(spkts, 1.0)
    dinpkt = dur / max(dpkts, 1.0)
    smean = sbytes / max(spkts, 1.0)
    dmean = dbytes / max(dpkts, 1.0)

    known = {
        "dur": dur,
        "spkts": spkts,
        "dpkts": dpkts,
        "sbytes": sbytes,
        "dbytes": dbytes,
        "rate": rate,
        "sttl": 64.0,
        "dttl": 64.0,
        "sload": sload,
        "dload": dload,
        "sloss": 0.0,
        "dloss": 0.0,
        "sinpkt": sinpkt,
        "dinpkt": dinpkt,
        "sjit": special_char_count * 0.1,
        "djit": special_char_count * 0.05 + resp_is_error * 0.2,
        "swin": 255.0,
        "stcpb": 1000.0 + safe_num(row, "seq_id", 0) * 10.0,
        "dtcpb": 2000.0 + safe_num(row, "seq_id", 0) * 10.0,
        "dwin": 255.0,
        "tcprtt": 0.05 + resp_is_error * 0.02,
        "synack": 0.02,
        "ackdat": 0.03,
        "smean": smean,
        "dmean": dmean,
        "trans_depth": 1.0 + has_json_body + has_password_keyword,
        "response_body_len": min(request_text_len, 10000),
        "ct_srv_src": 1.0 + has_login_keyword + has_captcha_keyword,
        "ct_state_ttl": 1.0,
        "ct_dst_ltm": 1.0 + has_login_keyword,
        "ct_src_dport_ltm": 1.0,
        "ct_dst_sport_ltm": 1.0,
        "ct_dst_src_ltm": 1.0,
        "is_ftp_login": 0.0,
        "ct_ftp_cmd": 0.0,
        "ct_flw_http_mthd": 2.0 if is_post else (1.0 if is_get else 0.0),
        "ct_src_ltm": 1.0 + has_password_keyword + has_token_keyword,
        "ct_srv_dst": 1.0 + has_admin_keyword,
        "is_sm_ips_ports": 0.0,
    }

    if col in known:
        return known[col]

    c = col.lower()
    if "byte" in c:
        return sbytes
    if "pkt" in c:
        return spkts
    if "load" in c:
        return sload
    if "ttl" in c:
        return 64.0
    if "mean" in c:
        return smean
    if "jit" in c:
        return special_char_count * 0.1
    if c.startswith("ct_"):
        return 1.0 + has_login_keyword + has_password_keyword
    if c.startswith("is_"):
        return 0.0

    return 0.0


def main():
    parser = argparse.ArgumentParser(description="将当前 model_input 转成旧模型兼容输入")
    parser.add_argument("--input", required=True, help="当前 model_input.csv 路径")
    parser.add_argument("--preprocessor", required=True, help="旧 preprocessor.joblib 路径")
    parser.add_argument("--output", required=True, help="输出 compat_old_input.csv 路径")
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)

    df = pd.read_csv(input_path)
    preprocessor = joblib.load(args.preprocessor)

    numeric_cols, categorical_cols, categorical_choices = load_preprocessor_schema(preprocessor)

    logging.info("输入记录数: %d", len(df))
    logging.info("旧模型 numeric_cols 数量: %d", len(numeric_cols))
    logging.info("旧模型 categorical_cols 数量: %d", len(categorical_cols))

    out_rows = []

    for _, row in df.iterrows():
        row_dict = row.to_dict()

        out = {
            "file_id": row_dict.get("file_id"),
            "seq_id": row_dict.get("seq_id"),
        }

        for col in categorical_cols:
            out[col] = choose_category(col, categorical_choices, row_dict)

        for col in numeric_cols:
            out[col] = build_numeric_value(col, row_dict)

        out_rows.append(out)

    out_df = pd.DataFrame(out_rows)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    out_df.to_csv(output_path, index=False, encoding="utf-8-sig")

    logging.info("输出记录数: %d", len(out_df))
    logging.info("输出文件: %s", output_path)

    preview_cols = ["file_id", "seq_id"]
    for c in ["proto", "service", "state"]:
        if c in out_df.columns:
            preview_cols.append(c)

    print("=" * 60)
    print(out_df[preview_cols].head(3))
    print("=" * 60)


if __name__ == "__main__":
    main()
