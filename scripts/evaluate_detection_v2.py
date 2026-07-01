from __future__ import annotations

import argparse
import json
import random
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Tuple
from urllib.parse import quote_plus

from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score

from security_detection_v2 import DetectionEngineV2, extract_request_from_record, is_simple_page_view, payload_model_text
from train_payload_model_v2 import make_record

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SERVER_ROWS = PROJECT_ROOT / "output" / "server_all_joined_rows.json"
DEFAULT_OUT = PROJECT_ROOT / "output" / "detection_v2"


def make_adversarial_cases() -> List[Tuple[str, Dict[str, Any], str]]:
    cases: List[Tuple[str, Dict[str, Any], str]] = []
    normal_texts = [
        ("/api/search?q=union+station", "normal search phrase containing union"),
        ("/api/search?q=script+writing+tutorial", "normal search phrase containing script"),
        ("/api/search?q=select+a+city", "normal search phrase containing select"),
        ("/api/comment", "json normal comment with <b>safe html</b>"),
        ("/sql", "open SQL test page"),
        ("/xss", "open XSS test page"),
        ("/upload", "open upload page"),
        ("/api/auth/login", "normal failed login"),
    ]
    for uri, note in normal_texts:
        if uri == "/api/comment":
            rec = make_record("POST", uri, '{"content":"I like script writing and union station"}', "application/json", 200)
        elif uri == "/api/auth/login":
            rec = make_record("POST", uri, '{"username":"admin","password":"wrongpass"}', "application/json", 401)
        else:
            rec = make_record("GET", uri, "", "", 200)
        cases.append(("normal", rec, note))

    attacks = [
        ("SQL注入", make_record("GET", "/api/item?id=1%27%20OR%20%271%27%3D%271", "", "", 500), "encoded sqli"),
        ("SQL注入", make_record("POST", "/api/auth/login", '{"username":"a","password":"x\" OR \"1\"=\"1"}', "application/json", 200), "double quote sqli"),
        ("XSS", make_record("GET", "/api/search?q=%3Csvg%2Fonload%3Dalert%281%29%3E", "", "", 200), "encoded svg xss"),
        ("命令注入", make_record("POST", "/api/system/ping", '{"host":"127.0.0.1%3Bwhoami"}', "application/json", 200), "encoded command"),
        ("路径遍历", make_record("GET", "/download?file=%252e%252e%252f%252e%252e%252fetc%252fpasswd", "", "", 200), "double encoded traversal"),
        ("SSRF", make_record("GET", "/api/proxy?url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F", "", "", 200), "metadata ssrf"),
        ("SSTI", make_record("GET", "/api/render?name=%7B%7B7*7%7D%7D", "", "", 200), "encoded ssti"),
        ("XXE", make_record("POST", "/api/xml/import", "<!DOCTYPE a [<!ENTITY b SYSTEM 'file:///etc/passwd'>]><a>&b;</a>", "application/xml", 500), "xxe"),
        ("危险文件上传", make_record("POST", "/api/upload", "filename=shell.phtml\r\n<?php phpinfo();?>", "multipart/form-data", 200), "phtml upload"),
        ("反序列化", make_record("POST", "/api/object/load", '{"payload":"aced000573720011"}', "application/json", 500), "java serialized"),
        ("GraphQL探测", make_record("POST", "/graphql", '{"query":"{__schema{types{name}}}"}', "application/json", 200), "graphql introspection"),
    ]
    cases.extend(attacks)
    return cases


def expected_label_for_server(row: Dict[str, Any]) -> str | None:
    ev = extract_request_from_record(row)
    uri = str(ev.get("uri") or "")
    body = str(ev.get("body") or "")
    text = (uri + "\n" + body).lower()
    if "<!doctype" in text or "<!entity" in text:
        return "XXE"
    if any(x in text for x in ["whoami", "cat /etc/passwd", "powershell", ";whoami", "&& cat"]):
        return "命令注入"
    if is_simple_page_view(ev):
        return "normal"
    if "<script" in text or "onerror" in text or "onload" in text or "javascript:" in text:
        return "XSS"
    if "union select" in text or " or 1=1" in text or "' or" in text or "\" or" in text or "information_schema" in text or "sleep(" in text:
        return "SQL注入"
    if "../" in text or "%2e%2e" in text or "etc/passwd" in text or "win.ini" in text:
        return "路径遍历"
    if "{{7*7" in text or "__class__" in text:
        return "SSTI"
    if "filename=" in text and any(ext in text for ext in [".php", ".jsp", ".aspx", ".ps1", ".sh"]):
        return "危险文件上传"
    return None


def evaluate_records(engine: DetectionEngineV2, labeled: List[Tuple[str, Dict[str, Any], str]]) -> Dict[str, Any]:
    y_true=[]; y_pred=[]; decisions=[]; rows=[]
    for label, rec, note in labeled:
        out = engine.detect(rec)
        pred = out["fusion"].get("attack_type") or out["payload"].get("label") or "unknown"
        if out["fusion"].get("decision") == "raw_only":
            pred = "normal"
        y_true.append(label); y_pred.append(pred); decisions.append(out["fusion"].get("decision"))
        rows.append({"expected":label,"pred":pred,"decision":out["fusion"].get("decision"),"note":note,"uri":extract_request_from_record(rec).get("uri"),"score":out["fusion"].get("final_score"),"payload":out["payload"],"poc":out["poc_matches"],"fusion":out["fusion"],"evidence":out["fusion"].get("evidence")})
    labels=sorted(set(y_true)|set(y_pred))
    return {"accuracy":accuracy_score(y_true,y_pred),"macro_f1":f1_score(y_true,y_pred,average="macro"),"report":classification_report(y_true,y_pred,digits=4,zero_division=0),"confusion":confusion_matrix(y_true,y_pred,labels=labels).tolist(),"labels":labels,"decision_counts":dict(Counter(decisions)),"rows":rows}


def main() -> None:
    parser=argparse.ArgumentParser(description="Evaluate detection v2")
    parser.add_argument("--out-dir", default=str(DEFAULT_OUT))
    args=parser.parse_args()
    out_dir=Path(args.out_dir); out_dir.mkdir(parents=True,exist_ok=True)
    engine=DetectionEngineV2()

    adversarial=make_adversarial_cases()
    adv_eval=evaluate_records(engine, adversarial)

    server_labeled=[]
    if SERVER_ROWS.exists():
        rows=json.loads(SERVER_ROWS.read_text(encoding="utf-8-sig"))
        for r in rows:
            lab=expected_label_for_server(r)
            if lab:
                server_labeled.append((lab,r,str(r.get("case_id"))))
    server_eval=evaluate_records(engine, server_labeled)
    # Full server suppression summary, without requiring labels for every row.
    full=[]
    if SERVER_ROWS.exists():
        for r in json.loads(SERVER_ROWS.read_text(encoding="utf-8-sig")):
            out=engine.detect(r)
            ev=extract_request_from_record(r)
            full.append({"case_id":r.get("case_id"),"uri":ev.get("uri"),"old_type":r.get("attack_type"),"decision":out["fusion"].get("decision"),"attack_type":out["fusion"].get("attack_type"),"score":out["fusion"].get("final_score"),"evidence":out["fusion"].get("evidence")})
    summary={"adversarial":{k:v for k,v in adv_eval.items() if k!="rows"},"server_labeled":{k:v for k,v in server_eval.items() if k!="rows"},"server_labeled_count":len(server_labeled),"full_server_decisions":dict(Counter(x["decision"] for x in full)),"full_server_total":len(full)}
    (out_dir/"evaluation_summary.json").write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding="utf-8")
    (out_dir/"adversarial_rows.json").write_text(json.dumps(adv_eval["rows"],ensure_ascii=False,indent=2),encoding="utf-8")
    (out_dir/"server_labeled_rows.json").write_text(json.dumps(server_eval["rows"],ensure_ascii=False,indent=2),encoding="utf-8")
    (out_dir/"server_full_decisions.json").write_text(json.dumps(full,ensure_ascii=False,indent=2),encoding="utf-8")
    print(json.dumps(summary,ensure_ascii=False,indent=2))
    print("\nAdversarial report:\n", adv_eval["report"])
    print("\nServer labeled report:\n", server_eval["report"])

if __name__ == "__main__":
    main()

