import argparse
import json
from pathlib import Path

import joblib


def main():
    parser = argparse.ArgumentParser(description="检查旧预处理器需要的输入列")
    parser.add_argument("--preprocessor", required=True, help="preprocessor.joblib 路径")
    parser.add_argument("--out-json", required=True, help="输出 schema json 路径")
    args = parser.parse_args()

    preprocessor = joblib.load(args.preprocessor)

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

    schema = {
        "numeric_cols": numeric_cols,
        "categorical_cols": categorical_cols,
        "categorical_choices": categorical_choices,
    }

    out_path = Path(args.out_json)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(schema, ensure_ascii=False, indent=2), encoding="utf-8")

    print("=" * 60)
    print("numeric_cols 数量:", len(numeric_cols))
    print("categorical_cols 数量:", len(categorical_cols))
    print("=" * 60)
    print("numeric_cols:")
    print(numeric_cols)
    print("=" * 60)
    print("categorical_cols:")
    print(categorical_cols)
    print("=" * 60)
    print("categorical_choices:")
    print(json.dumps(categorical_choices, ensure_ascii=False, indent=2))
    print("=" * 60)
    print("schema 已输出到:", out_path)


if __name__ == "__main__":
    main()
