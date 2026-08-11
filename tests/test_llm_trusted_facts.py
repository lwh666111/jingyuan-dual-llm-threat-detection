from scripts.build_result_db import (
    normalize_attack_event_time,
    normalize_attack_ip,
    normalize_attack_type,
    normalize_target_interface,
)
from scripts.llm_analyzer_daemon import normalize_analysis


def test_llm_cannot_overwrite_packet_facts():
    case = {
        "case_id": "b.42",
        "file_id": "1.1.99",
        "seq_id": 2,
        "source_ip": "203.0.113.8",
        "destination_ip": "192.0.2.10",
        "method": "GET",
        "uri": "/download?file=../../etc/passwd",
        "attack_type": "路径遍历",
        "export_time": "2026-08-11T10:20:06",
    }
    hallucinated = {
        "source_ip": "192.168.1.100",
        "destination_ip": "192.168.1.80",
        "attack_interface": "eth0",
        "attack_method": "SSH brute force attack",
        "attack_path": "POST /login",
        "attack_time": "2026-08-10T00:00:00",
        "summary": "model explanation",
    }

    result = normalize_analysis(hallucinated, case, "", "", "test-model")

    assert result["source_ip"] == "203.0.113.8"
    assert result["destination_ip"] == "192.0.2.10"
    assert result["attack_interface"] == case["uri"]
    assert result["attack_method"] == "路径遍历"
    assert result["attack_path"] == f"GET {case['uri']}"
    assert result["attack_time"] == "2026-08-11T10:20:06"
    assert "203.0.113.8" in result["summary"]
    assert "路径遍历" in result["summary"]
    assert "192.168.1.100" not in result["summary"]
    assert result["llm_explanation"] == "model explanation"


def test_database_normalizers_prefer_trusted_case_fields():
    case = {
        "source_ip": "203.0.113.8",
        "uri": "/api/search?q=test",
        "attack_type": "SQL注入",
        "export_time": "2026-08-11T10:20:06",
    }
    hallucinated = {
        "source_ip": "10.0.0.9",
        "attack_interface": "eth0",
        "attack_method": "SSH brute force attack",
        "attack_time": "2026-08-10T00:00:00",
    }

    assert normalize_attack_ip(case, hallucinated) == "203.0.113.8"
    assert normalize_target_interface(case, hallucinated) == "/api/search?q=test"
    assert normalize_attack_type(hallucinated, case) == "SQL注入"
    assert normalize_attack_event_time(case, hallucinated) == "2026-08-11T10:20:06"


def test_llm_verdict_and_percent_confidence_are_canonicalized():
    case = {
        "case_id": "raw:test",
        "source_ip": "203.0.113.8",
        "destination_ip": "192.0.2.10",
        "method": "GET",
        "uri": "/search?q=xss",
        "attack_type": "XSS跨站脚本",
    }
    result = normalize_analysis(
        {"verdict": "确认存在攻击行为", "confidence": 96, "severity": "high"},
        case,
        "",
        "",
        "test-model",
    )

    assert result["verdict"] == "attack"
    assert result["confidence"] == 0.96
