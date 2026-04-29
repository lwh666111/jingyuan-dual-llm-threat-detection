import argparse
import csv
import json
import logging
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import torch
import torch.nn as nn

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

MODEL_NAME = "old_unsw_mlp_direct_compat_mode"


class MLP(nn.Module):
    def __init__(self, input_dim):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(input_dim, 256),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(256, 128),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(64, 1),
        )

    def forward(self, x):
        return self.net(x)


def load_required_cols(preprocessor):
    numeric_cols = []
    categorical_cols = []
    for name, transformer, cols in preprocessor.transformers_:
        if name == "num":
            numeric_cols = list(cols)
        elif name == "cat":
            categorical_cols = list(cols)
    return numeric_cols, categorical_cols


def write_jsonl(records, path: Path):
    with path.open("w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")


def write_csv(records, path: Path):
    if not records:
        return
    fieldnames = list(records[0].keys())
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in records:
            writer.writerow(r)


def main():
    parser = argparse.ArgumentParser(description="鐩存帴杩愯鏃фā鍨?compatibility mode 鎺ㄧ悊")
    parser.add_argument("--input", required=True, help="old_model_input.csv")
    parser.add_argument("--preprocessor", required=True, help="preprocessor.joblib")
    parser.add_argument("--model", required=True, help="best_mlp.pth")
    parser.add_argument("--output-jsonl", required=True)
    parser.add_argument("--output-csv", required=True)
    parser.add_argument("--label-threshold", type=float, default=0.46)
    args = parser.parse_args()

    df = pd.read_csv(args.input)
    logging.info("杈撳叆璁板綍鏁? %d", len(df))

    preprocessor = joblib.load(args.preprocessor)
    numeric_cols, categorical_cols = load_required_cols(preprocessor)
    required_cols = categorical_cols + numeric_cols

    missing = [c for c in required_cols if c not in df.columns]
    if missing:
        raise ValueError(f"杈撳叆缂哄皯鏃фā鍨嬮渶瑕佺殑鍒? {missing}")

    meta_df = df[["file_id", "seq_id"]].copy()
    feature_df = df[required_cols].copy()

    X = preprocessor.transform(feature_df)
    X = X.toarray() if hasattr(X, "toarray") else X
    logging.info("鍙樻崲鍚庣煩闃?shape: %s", X.shape)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    model = MLP(X.shape[1]).to(device)
    state_dict = torch.load(args.model, map_location=device)
    model.load_state_dict(state_dict)
    model.eval()

    X_tensor = torch.tensor(X, dtype=torch.float32).to(device)
    with torch.no_grad():
        logits = model(X_tensor)
        probs = torch.sigmoid(logits).cpu().numpy().flatten()

    results = []
    for idx, prob in enumerate(probs):
        label = "suspicious" if prob >= args.label_threshold else "benign"
        results.append(
            {
                "file_id": str(meta_df.iloc[idx]["file_id"]),
                "seq_id": int(meta_df.iloc[idx]["seq_id"]),
                "score": float(round(float(prob), 6)),
                "label": label,
                "model_name": MODEL_NAME,
            }
        )

    output_jsonl = Path(args.output_jsonl)
    output_csv = Path(args.output_csv)
    output_jsonl.parent.mkdir(parents=True, exist_ok=True)

    write_jsonl(results, output_jsonl)
    write_csv(results, output_csv)

    logging.info("score 鏈€灏忓€? %.6f", float(np.min(probs)))
    logging.info("score 鏈€澶у€? %.6f", float(np.max(probs)))
    logging.info("score 骞冲潎鍊? %.6f", float(np.mean(probs)))
    logging.info("杈撳嚭 jsonl: %s", output_jsonl)
    logging.info("杈撳嚭 csv: %s", output_csv)

    for item in results[:5]:
        logging.info(
            "seq=%s score=%s label=%s model=%s",
            item["seq_id"],
            item["score"],
            item["label"],
            item["model_name"],
        )


if __name__ == "__main__":
    main()


