import argparse
import csv
import json
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent


def detect_project_root() -> Path:
    if (SCRIPT_DIR / "app.py").exists():
        return SCRIPT_DIR
    if (SCRIPT_DIR.parent / "app.py").exists():
        return SCRIPT_DIR.parent
    return SCRIPT_DIR


PROJECT_ROOT = detect_project_root()


def print_step_title(title: str):
    print("\n" + "=" * 80)
    print(title)
    print("=" * 80)


def _safe_console_text(text: str) -> str:
    if text is None:
        return ""
    enc = sys.stdout.encoding or "utf-8"
    return text.encode(enc, errors="replace").decode(enc, errors="replace")


def resolve_default_model_paths():
    local_models = PROJECT_ROOT / "models"
    local_pre = local_models / "preprocessor.joblib"
    local_mdl = local_models / "best_mlp.pth"
    if local_pre.exists() and local_mdl.exists():
        return local_pre, local_mdl

    fallback_models = PROJECT_ROOT.parent / "traffic_mlp" / "models"
    return fallback_models / "preprocessor.joblib", fallback_models / "best_mlp.pth"


def script_path(name: str) -> Path:
    return SCRIPT_DIR / name


def run_command(cmd, cwd=None):
    print_step_title("执行命令")
    print(" ".join(str(x) for x in cmd))
    result = subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    print("\n[STDOUT]")
    stdout_text = result.stdout if result.stdout.strip() else "(无)"
    print(_safe_console_text(stdout_text))
    print("\n[STDERR]")
    stderr_text = result.stderr if result.stderr.strip() else "(无)"
    print(_safe_console_text(stderr_text))
    if result.returncode != 0:
        raise RuntimeError(f"命令执行失败，返回码={result.returncode}")
    return result


def preview_jsonl(path: Path, limit=3, keys=None):
    print_step_title(f"预览 JSONL: {path}")
    if not path.exists():
        print("文件不存在")
        return
    count = 0
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            if keys:
                obj = {k: obj.get(k) for k in keys}
            print(json.dumps(obj, ensure_ascii=False, indent=2))
            count += 1
            if count >= limit:
                break
    if count == 0:
        print("(空文件)")


def preview_csv(path: Path, limit=3):
    print_step_title(f"预览 CSV: {path}")
    if not path.exists():
        print("文件不存在")
        return
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for idx, row in enumerate(reader):
            print(json.dumps(row, ensure_ascii=False, indent=2))
            if idx + 1 >= limit:
                break


def count_jsonl(path: Path) -> int:
    if not path.exists():
        return 0
    count = 0
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                count += 1
    return count


def count_csv_rows(path: Path) -> int:
    if not path.exists():
        return 0
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        return sum(1 for _ in reader)


def _case_id_sort_key(case_id: str):
    if isinstance(case_id, str) and case_id.startswith("b."):
        try:
            return int(case_id.split(".", 1)[1])
        except Exception:
            return 10**9
    return 10**9


def load_manifest_case_ids(manifest_path: Path):
    if not manifest_path.exists():
        return []
    ids = []
    with manifest_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                cid = obj.get("case_id")
                if cid:
                    ids.append(str(cid))
            except Exception:
                continue
    ids = list(dict.fromkeys(ids))
    ids.sort(key=_case_id_sort_key)
    return ids


def require_file(path: Path, description: str):
    if not path.exists():
        raise FileNotFoundError(f"{description} 不存在: {path}")
    print(f"[OK] {description}: {path}")


def main():
    default_pre, default_model = resolve_default_model_paths()

    parser = argparse.ArgumentParser(
        description="新工作流演示：txt -> old_model_input -> old_model -> rerank -> demo_candidates"
    )
    parser.add_argument("--input-txt", required=True, help="输入 Wireshark txt 文件路径，例如 input/1.1.2.txt")
    parser.add_argument("--preprocessor", default=str(default_pre), help="旧 preprocessor.joblib 路径")
    parser.add_argument("--model", default=str(default_model), help="旧 best_mlp.pth 路径")
    parser.add_argument("--label-threshold", type=float, default=0.35, help="compat mode 标签阈值")
    parser.add_argument("--top-k", type=int, default=3, help="demo candidates 输出条数")
    parser.add_argument("--export-min-score", type=float, default=0.3, help="导出到 result 的最低 raw_score 阈值")
    parser.add_argument("--update-existing-export", action="store_true", help="导出到 result 时若已存在则覆盖更新")
    args = parser.parse_args()

    input_txt = Path(args.input_txt).resolve()
    if not input_txt.exists():
        raise FileNotFoundError(f"输入文件不存在: {input_txt}")

    preprocessor_path = Path(args.preprocessor).resolve()
    model_path = Path(args.model).resolve()

    required_scripts = [
        "extract_old_model_features_from_txt.py",
        "run_old_model_direct.py",
        "rerank_model_result.py",
        "build_demo_candidates.py",
        "export_demo_candidates_to_result.py",
    ]
    missing_scripts = [s for s in required_scripts if not script_path(s).exists()]
    if missing_scripts:
        raise FileNotFoundError(f"缺少脚本: {missing_scripts}")

    file_id = input_txt.stem
    output_dir = PROJECT_ROOT / "output" / f"demo_{file_id}"
    output_dir.mkdir(parents=True, exist_ok=True)

    print_step_title("演示模式说明")
    print("当前为旧模型兼容演示模式（新直提链路），输出仅用于流程验证，不代表最终检测效果。")
    print(f"输入文件: {input_txt}")
    print(f"file_id: {file_id}")
    print(f"输出目录: {output_dir}")
    print(f"旧预处理器: {preprocessor_path}")
    print(f"旧模型: {model_path}")

    require_file(preprocessor_path, "旧预处理器")
    require_file(model_path, "旧模型")

    old_schema_json = output_dir / "old_preprocessor_schema.json"
    old_input_csv = output_dir / f"{file_id}.old_model_input.csv"
    raw_index_jsonl = output_dir / f"{file_id}.raw_index.jsonl"
    model_result_jsonl = output_dir / f"{file_id}.model_result.jsonl"
    model_result_csv = output_dir / f"{file_id}.model_result.csv"
    reranked_jsonl = output_dir / f"{file_id}.model_result_reranked.jsonl"
    demo_candidates_jsonl = output_dir / f"{file_id}.demo_candidates.jsonl"
    result_dir = PROJECT_ROOT / "result"
    manifest_jsonl = result_dir / "manifest.jsonl"

    print_step_title("Step 1 / 5 - extract_old_model_features_from_txt.py")
    run_command(
        [
            sys.executable,
            str(script_path("extract_old_model_features_from_txt.py")),
            "--input",
            str(input_txt),
            "--preprocessor",
            str(preprocessor_path),
            "--output-dir",
            str(output_dir),
        ]
    )
    require_file(old_schema_json, "旧预处理器 schema")
    require_file(old_input_csv, "old_model_input csv")
    require_file(raw_index_jsonl, "raw_index jsonl")
    preview_csv(old_input_csv, limit=3)
    preview_jsonl(raw_index_jsonl, limit=3, keys=["file_id", "seq_id", "method", "uri", "status_code"])

    print_step_title("Step 2 / 5 - run_old_model_direct.py")
    run_command(
        [
            sys.executable,
            str(script_path("run_old_model_direct.py")),
            "--input",
            str(old_input_csv),
            "--preprocessor",
            str(preprocessor_path),
            "--model",
            str(model_path),
            "--output-jsonl",
            str(model_result_jsonl),
            "--output-csv",
            str(model_result_csv),
            "--label-threshold",
            str(args.label_threshold),
        ]
    )
    require_file(model_result_jsonl, "model_result jsonl")
    require_file(model_result_csv, "model_result csv")
    preview_jsonl(model_result_jsonl, limit=5, keys=["file_id", "seq_id", "score", "label", "model_name"])

    print_step_title("Step 3 / 5 - rerank_model_result.py")
    run_command(
        [
            sys.executable,
            str(script_path("rerank_model_result.py")),
            "--input",
            str(model_result_jsonl),
            "--output",
            str(reranked_jsonl),
        ]
    )
    require_file(reranked_jsonl, "reranked model_result jsonl")
    preview_jsonl(reranked_jsonl, limit=5, keys=["file_id", "seq_id", "raw_score", "norm_score", "rank", "label"])

    print_step_title("Step 4 / 5 - build_demo_candidates.py")
    run_command(
        [
            sys.executable,
            str(script_path("build_demo_candidates.py")),
            "--parsed",
            str(raw_index_jsonl),
            "--model-input",
            str(raw_index_jsonl),
            "--reranked-result",
            str(reranked_jsonl),
            "--output",
            str(demo_candidates_jsonl),
            "--top-k",
            str(args.top_k),
        ]
    )
    require_file(demo_candidates_jsonl, "demo_candidates jsonl")
    preview_jsonl(
        demo_candidates_jsonl,
        limit=3,
        keys=["file_id", "seq_id", "rank", "raw_score", "norm_score", "method", "uri", "status_code"],
    )

    print_step_title("Step 5 / 5 - export_demo_candidates_to_result.py")
    before_case_ids = load_manifest_case_ids(manifest_jsonl)
    export_cmd = [
        sys.executable,
        str(script_path("export_demo_candidates_to_result.py")),
        "--input",
        str(demo_candidates_jsonl),
        "--result-dir",
        str(result_dir),
        "--min-score",
        str(args.export_min_score),
    ]
    if args.update_existing_export:
        export_cmd.append("--update-existing")

    run_command(export_cmd)
    require_file(manifest_jsonl, "result manifest")
    after_case_ids = load_manifest_case_ids(manifest_jsonl)
    before_case_set = set(before_case_ids)
    new_case_ids = [cid for cid in after_case_ids if cid not in before_case_set]
    result_export_count = len(new_case_ids)

    print_step_title("工作流总结")
    extracted_count = count_jsonl(raw_index_jsonl)
    old_input_count = count_csv_rows(old_input_csv)
    model_result_count = count_jsonl(model_result_jsonl)
    reranked_count = count_jsonl(reranked_jsonl)
    demo_candidates_count = count_jsonl(demo_candidates_jsonl)
    print(f"提取请求数量(raw_index): {extracted_count}")
    print(f"old_model_input 行数: {old_input_count}")
    print(f"model_result 数量: {model_result_count}")
    print(f"reranked 数量: {reranked_count}")
    print(f"demo_candidates 数量: {demo_candidates_count}")
    print(f"result 导出阈值(raw_score): {args.export_min_score}")
    print(f"result 新导出 case 数量: {result_export_count}")
    print(f"result 新导出的 case_id: {new_case_ids if new_case_ids else '无'}")

    print("\n前 3 条 demo_candidates 摘要：")
    preview_jsonl(
        demo_candidates_jsonl,
        limit=3,
        keys=["file_id", "seq_id", "rank", "raw_score", "norm_score", "uri", "method"],
    )

    print_step_title("演示完成")
    print("新工作流已执行完毕。")
    print(f"所有结果输出在: {output_dir}")


if __name__ == "__main__":
    main()
