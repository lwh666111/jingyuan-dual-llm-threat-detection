from __future__ import annotations

import json
import random
from pathlib import Path
from typing import Dict, List

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, f1_score
from sklearn.model_selection import train_test_split

FEATURES = [
    "request_count",
    "distinct_path_count",
    "login_request_count",
    "login_fail_count",
    "not_found_count",
    "user_agent_count",
    "payload_hit_count",
    "status_5xx_count",
]


def sample_range(lo: int, hi: int) -> int:
    return random.randint(lo, hi)


def row(label: str, **kwargs) -> Dict:
    data = {k: 0 for k in FEATURES}
    data.update(kwargs)
    data["label"] = label
    return data


def generate_samples(n: int = 24000) -> List[Dict]:
    random.seed(20260701)
    rows: List[Dict] = []
    for _ in range(n // 6):
        rows.append(
            row(
                "normal",
                request_count=sample_range(1, 14),
                distinct_path_count=sample_range(1, 5),
                login_request_count=sample_range(0, 3),
                login_fail_count=sample_range(0, 2),
                not_found_count=sample_range(0, 2),
                user_agent_count=sample_range(1, 3),
                payload_hit_count=0,
                status_5xx_count=sample_range(0, 1),
            )
        )
        rows.append(
            row(
                "bruteforce",
                request_count=sample_range(10, 80),
                distinct_path_count=sample_range(1, 5),
                login_request_count=sample_range(8, 70),
                login_fail_count=sample_range(8, 70),
                not_found_count=sample_range(0, 3),
                user_agent_count=sample_range(1, 4),
                payload_hit_count=sample_range(0, 6),
                status_5xx_count=sample_range(0, 5),
            )
        )
        rows.append(
            row(
                "scan",
                request_count=sample_range(20, 180),
                distinct_path_count=sample_range(12, 120),
                login_request_count=sample_range(0, 8),
                login_fail_count=sample_range(0, 6),
                not_found_count=sample_range(8, 120),
                user_agent_count=sample_range(1, 10),
                payload_hit_count=sample_range(0, 8),
                status_5xx_count=sample_range(0, 10),
            )
        )
        rows.append(
            row(
                "high_frequency",
                request_count=sample_range(160, 800),
                distinct_path_count=sample_range(1, 30),
                login_request_count=sample_range(0, 30),
                login_fail_count=sample_range(0, 20),
                not_found_count=sample_range(0, 40),
                user_agent_count=sample_range(1, 8),
                payload_hit_count=sample_range(0, 12),
                status_5xx_count=sample_range(0, 60),
            )
        )
        rows.append(
            row(
                "dir_probe",
                request_count=sample_range(12, 120),
                distinct_path_count=sample_range(8, 80),
                login_request_count=sample_range(0, 4),
                login_fail_count=sample_range(0, 3),
                not_found_count=sample_range(10, 100),
                user_agent_count=sample_range(1, 6),
                payload_hit_count=sample_range(0, 4),
                status_5xx_count=sample_range(0, 6),
            )
        )
        rows.append(
            row(
                "payload_burst",
                request_count=sample_range(4, 60),
                distinct_path_count=sample_range(1, 12),
                login_request_count=sample_range(0, 15),
                login_fail_count=sample_range(0, 12),
                not_found_count=sample_range(0, 8),
                user_agent_count=sample_range(1, 5),
                payload_hit_count=sample_range(4, 40),
                status_5xx_count=sample_range(0, 20),
            )
        )
    return rows


def main() -> None:
    project_root = Path(__file__).resolve().parent.parent
    output_model = project_root / "models" / "behavior_model_v2.joblib"
    output_report = project_root / "output" / "detection_v2" / "behavior_model_report.json"
    output_model.parent.mkdir(parents=True, exist_ok=True)
    output_report.parent.mkdir(parents=True, exist_ok=True)

    samples = generate_samples()
    x = np.array([[r[k] for k in FEATURES] for r in samples], dtype=float)
    y = np.array([r["label"] for r in samples])
    x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.25, random_state=42, stratify=y)
    model = RandomForestClassifier(n_estimators=180, max_depth=10, random_state=42, class_weight="balanced_subsample")
    model.fit(x_train, y_train)
    pred = model.predict(x_test)
    report = {
        "features": FEATURES,
        "samples": len(samples),
        "accuracy": float(accuracy_score(y_test, pred)),
        "macro_f1": float(f1_score(y_test, pred, average="macro")),
        "classification_report": classification_report(y_test, pred, digits=4),
        "labels": sorted(set(y)),
    }
    joblib.dump({"model": model, "features": FEATURES, "labels": report["labels"]}, output_model)
    output_report.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
