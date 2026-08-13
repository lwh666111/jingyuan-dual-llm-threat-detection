import argparse
import json
import re
from datetime import datetime
from pathlib import Path

from web_attack_rules import apply_rule_signal, detect_request_attack, is_plain_auth_attempt
from security_detection_v2 import DetectionEngineV2

DEFAULT_LLM_TASK = (
    "\u8bf7\u5224\u65ad\u8be5\u8bf7\u6c42\u662f\u5426\u4e3a\u653b\u51fb\u884c\u4e3a\uff0c"
    "\u5982\u662f\u8bf7\u7ed9\u51fa\u653b\u51fb\u7c7b\u578b\u3001\u5224\u5b9a\u4f9d\u636e\u3001"
    "\u98ce\u9669\u7b49\u7ea7\u548c\u5904\u7f6e\u5efa\u8bae\u3002"
)


def read_jsonl(path: Path, *, tolerate_invalid: bool = False):
    if not path.exists():
        return
    with path.open("r", encoding="utf-8-sig") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if line:
                try:
                    value = json.loads(line)
                except json.JSONDecodeError as exc:
                    if tolerate_invalid:
                        print(f"[WARN] skip invalid JSONL line: {path}:{line_no}: {exc}")
                        continue
                    raise
                if not isinstance(value, dict):
                    if tolerate_invalid:
                        print(f"[WARN] skip non-object JSONL line: {path}:{line_no}")
                        continue
                    raise ValueError(f"JSONL record must be an object: {path}:{line_no}")
                yield value


def write_jsonl_append(path: Path, records):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")


def write_jsonl(path: Path, records):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")


def load_manifest(manifest_path: Path):
    # A disk-full interruption can leave a partial final line. Keep valid history
    # available and rewrite the manifest after this export instead of blocking all
    # subsequent traffic forever.
    records = list(read_jsonl(manifest_path, tolerate_invalid=True)) if manifest_path.exists() else []
    existing_keys = set()
    key_to_idx = {}
    max_case_num = 0

    for idx, r in enumerate(records):
        try:
            key = (str(r.get("file_id")), int(r.get("seq_id")))
            existing_keys.add(key)
            key_to_idx[key] = idx
        except Exception:
            pass

        case_id = str(r.get("case_id", ""))
        if case_id.startswith("b."):
            try:
                num = int(case_id.split(".", 1)[1])
                max_case_num = max(max_case_num, num)
            except Exception:
                pass
    return records, existing_keys, key_to_idx, max_case_num


def ensure_text(path: Path, text: str):
    path.write_text(text or "", encoding="utf-8")


def get_candidate_score(cand: dict) -> float:
    for key in ("raw_score", "score", "norm_score"):
        try:
            value = cand.get(key)
            if value is None:
                continue
            return float(value)
        except Exception:
            continue
    return 0.0


def infer_attack_type(cand: dict) -> str:
    if cand.get("attack_type"):
        return str(cand.get("attack_type"))

    text = "\n".join(
        [
            str(cand.get("uri") or ""),
            str(cand.get("request_text") or ""),
            str(cand.get("raw_request_block") or ""),
        ]
    ).lower()
    rules = [
        (
            r"(?:\bor\b\s+1=1|union\s+select|information_schema|sleep\(|benchmark\(|ascii\s*\(|substr\s*\(|database\s*\(|\band\b.+--|'\s*or\s*'?\d)",
            "\u0053\u0051\u004c\u6ce8\u5165",
        ),
        (r"(<script|javascript:|onerror=|onload=)", "XSS"),
        (r"(\.\./|\.\.\\|/etc/passwd|\\windows\\system32)", "\u8def\u5f84\u904d\u5386"),
        (r"(cmd\.exe|/bin/sh|powershell|;\s*cat\s+)", "\u547d\u4ee4\u6ce8\u5165"),
        (r"(multipart/form-data|\.php|\.jsp|\.aspx)", "\u6587\u4ef6\u4e0a\u4f20"),
        (r"(scan|masscan|nmap)", "\u7aef\u53e3\u626b\u63cf"),
    ]
    for pattern, label in rules:
        if re.search(pattern, text, re.I):
            return label
    return "\u53ef\u7591\u6d41\u91cf"

def main():
    parser = argparse.ArgumentParser(description="Export demo_candidates into result cases.")
    parser.add_argument("--input", required=True, help="Path to demo_candidates.jsonl.")
    parser.add_argument("--result-dir", default="result", help="Result root directory.")
    parser.add_argument("--min-score", type=float, default=0.3, help="Minimum export score based on raw_score/score.")
    parser.add_argument(
        "--plain-auth-min-score",
        type=float,
        default=0.88,
        help="Extra export threshold for one-off ordinary login attempts without attack signals.",
    )
    parser.add_argument("--update-existing", action="store_true", help="Overwrite an existing case with the same file_id and seq_id.")
    parser.add_argument(
        "--enable-v2-gate",
        action="store_true",
        help="Use v2 payload/POC/behavior fusion gate before exporting to result.",
    )
    parser.add_argument("--v2-model-path", default="models/payload_model_v2.joblib", help="v2 payload model path.")
    parser.add_argument("--v2-rules-path", default="rules/poc_rules.json", help="v2 POC rules path.")
    args = parser.parse_args()

    input_path = Path(args.input)
    result_dir = Path(args.result_dir)
    result_dir.mkdir(parents=True, exist_ok=True)

    manifest_path = result_dir / "manifest.jsonl"

    candidates = list(read_jsonl(input_path))
    manifest_records, existing_keys, key_to_idx, max_case_num = load_manifest(manifest_path)

    exported = []
    skipped = 0
    filtered_low_score = 0
    filtered_plain_auth = 0
    filtered_v2_raw = 0
    v2_candidate_count = 0
    v2_attack_event_count = 0
    updated_existing = 0
    updated_case_ids = []
    new_case_ids = []
    next_case_num = max_case_num + 1
    v2_engine = None
    if args.enable_v2_gate:
        project_root = Path(__file__).resolve().parent.parent
        v2_engine = DetectionEngineV2(
            model_path=(project_root / args.v2_model_path).resolve(),
            rules_path=(project_root / args.v2_rules_path).resolve(),
        )

    for cand in candidates:
        signal = detect_request_attack(cand)
        if signal:
            cand = apply_rule_signal(cand, signal)

        v2_detection = None
        if v2_engine is not None:
            v2_detection = v2_engine.detect(cand)
            fusion = v2_detection.get("fusion") or {}
            decision = str(fusion.get("decision") or "")
            if decision == "raw_only":
                filtered_v2_raw += 1
                continue
            if decision == "candidate":
                v2_candidate_count += 1
            if decision == "attack_event":
                v2_attack_event_count += 1
            cand = dict(cand)
            cand["v2_decision"] = decision
            cand["v2_final_score"] = fusion.get("final_score")
            cand["v2_risk_level"] = fusion.get("risk_level")
            cand["v2_payload_label"] = fusion.get("payload_label")
            cand["v2_payload_score"] = fusion.get("payload_score")
            cand["v2_behavior_type"] = fusion.get("behavior_type")
            cand["v2_behavior_score"] = fusion.get("behavior_score")
            cand["v2_poc_score"] = fusion.get("poc_score")
            cand["v2_evidence"] = fusion.get("evidence") or []
            cand["v2_poc_matches"] = fusion.get("poc_matches") or []
            if fusion.get("attack_type"):
                cand["attack_type"] = fusion.get("attack_type")
            if fusion.get("final_score") is not None:
                cand["raw_score"] = max(get_candidate_score(cand), float(fusion.get("final_score") or 0.0))
            cand["detection_source"] = "v2_fusion"

        score_value = get_candidate_score(cand)
        if not signal and is_plain_auth_attempt(cand) and score_value < args.plain_auth_min_score:
            filtered_plain_auth += 1
            continue

        if score_value < args.min_score:
            filtered_low_score += 1
            continue

        try:
            file_id = str(cand.get("file_id"))
            seq_id = int(cand.get("seq_id"))
        except Exception:
            skipped += 1
            continue

        key = (file_id, seq_id)
        if key in existing_keys:
            if not args.update_existing:
                skipped += 1
                continue
            idx = key_to_idx.get(key)
            existing_row = manifest_records[idx] if idx is not None else {}
            case_id = str(existing_row.get("case_id", ""))
            case_dir_from_manifest = str(existing_row.get("case_dir", "")).strip()
            if case_dir_from_manifest:
                case_dir = Path(case_dir_from_manifest)
            elif case_id:
                case_dir = result_dir / case_id
            else:
                case_id = f"b.{next_case_num}"
                case_dir = result_dir / case_id
                next_case_num += 1
            case_dir.mkdir(parents=True, exist_ok=True)
            is_update = True
        else:
            case_id = f"b.{next_case_num}"
            case_dir = result_dir / case_id
            case_dir.mkdir(parents=True, exist_ok=True)
            is_update = False

        export_time = datetime.now().isoformat(timespec="seconds")

        case_json = {
            "case_id": case_id,
            "file_id": file_id,
            "seq_id": seq_id,
            "rank": cand.get("rank"),
            "raw_score": cand.get("raw_score"),
            "original_model_score": cand.get("original_model_score"),
            "norm_score": cand.get("norm_score"),
            "label": cand.get("label"),
            "model_name": cand.get("model_name"),
            "detection_source": cand.get("detection_source") or "model",
            "rule_score": cand.get("rule_score"),
            "rule_reason": cand.get("rule_reason"),
            "v2_decision": cand.get("v2_decision"),
            "v2_final_score": cand.get("v2_final_score"),
            "v2_risk_level": cand.get("v2_risk_level"),
            "v2_payload_label": cand.get("v2_payload_label"),
            "v2_payload_score": cand.get("v2_payload_score"),
            "v2_behavior_type": cand.get("v2_behavior_type"),
            "v2_behavior_score": cand.get("v2_behavior_score"),
            "v2_poc_score": cand.get("v2_poc_score"),
            "v2_evidence": cand.get("v2_evidence"),
            "v2_poc_matches": cand.get("v2_poc_matches"),
            "source_ip": cand.get("source_ip"),
            "destination_ip": cand.get("destination_ip"),
            "source_port": cand.get("source_port"),
            "destination_port": cand.get("destination_port"),
            "method": cand.get("method"),
            "uri": cand.get("uri"),
            "host": cand.get("host"),
            "status_code": cand.get("status_code"),
            "request_text": cand.get("request_text"),
            "attack_type": infer_attack_type(cand),
            "llm_task": cand.get("llm_task") or DEFAULT_LLM_TASK,
            "export_time": export_time,
            "status": "pending",
            "llm_status": "pending",
        }

        ensure_text(case_dir / "request.txt", cand.get("raw_request_block", ""))
        ensure_text(case_dir / "response.txt", cand.get("raw_response_block", ""))
        ensure_text(case_dir / "case.json", json.dumps(case_json, ensure_ascii=False, indent=2))

        manifest_row = {
            "case_id": case_id,
            "file_id": file_id,
            "seq_id": seq_id,
            "source_ip": cand.get("source_ip"),
            "destination_ip": cand.get("destination_ip"),
            "uri": cand.get("uri"),
            "raw_score": cand.get("raw_score"),
            "original_model_score": cand.get("original_model_score"),
            "norm_score": cand.get("norm_score"),
            "label": cand.get("label"),
            "attack_type": cand.get("attack_type") or infer_attack_type(cand),
            "detection_source": cand.get("detection_source") or "model",
            "v2_decision": cand.get("v2_decision"),
            "v2_final_score": cand.get("v2_final_score"),
            "v2_risk_level": cand.get("v2_risk_level"),
            "status": "pending",
            "case_dir": str(case_dir.resolve()).replace("\\", "/"),
        }

        if is_update:
            idx = key_to_idx.get(key)
            if idx is not None:
                manifest_records[idx] = manifest_row
            else:
                manifest_records.append(manifest_row)
                key_to_idx[key] = len(manifest_records) - 1
            updated_existing += 1
            updated_case_ids.append(case_id)
        else:
            manifest_records.append(manifest_row)
            key_to_idx[key] = len(manifest_records) - 1
            existing_keys.add(key)
            exported.append(manifest_row)
            new_case_ids.append(case_id)
            next_case_num += 1

    if exported or updated_existing:
        write_jsonl(manifest_path, manifest_records)

    print("=" * 80)
    print("input candidates:", len(candidates))
    print("low-score filtered:", filtered_low_score)
    print("plain auth false-positive guard filtered:", filtered_plain_auth)
    print("v2 raw-only filtered:", filtered_v2_raw)
    print("v2 candidate exported:", v2_candidate_count)
    print("v2 attack-event exported:", v2_attack_event_count)
    print("existing/skipped:", skipped)
    print("new exported:", len(exported))
    print("updated existing:", updated_existing)
    print("export min score:", args.min_score)
    print("plain auth extra threshold:", args.plain_auth_min_score)
    print("result dir:", result_dir.resolve())
    print("new case_id list:", new_case_ids if new_case_ids else "none")
    print("updated case_id list:", updated_case_ids if updated_case_ids else "none")
    print("manifest path:", manifest_path.resolve())
    print("=" * 80)


if __name__ == "__main__":
    main()
