from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from situation_ai import fallback_report
from situation_core import SecurityAction, SituationCorrelator
from situation_store import MySQLSettings, MySQLSituationStore


DEMO_ASSET = "demo-finals-server"


SCENARIOS: List[Dict[str, Any]] = [
    {
        "source_ip": "203.0.113.84",
        "age_minutes": 4,
        "status": "open",
        "actions": [
            ("PORT_SCAN", 286, 0.91, "tcp:multiple", "tshark_syn_scan"),
            ("SERVICE_PROBE", 43, 0.86, "tcp:22,80,443,3306", "service_probe"),
            ("SSH_BRUTEFORCE", 67, 0.95, "tcp:22", "windows_ssh_log"),
            ("SQL_INJECTION", 12, 0.98, "/api/auth/login", "detection_v2"),
        ],
        "intent": "从暴露面侦察逐步转向凭据获取与数据库访问尝试",
        "conclusion": "该来源呈现完整的侦察、凭据攻击和漏洞利用链，属于正在推进的高置信连续攻击尝试。",
    },
    {
        "source_ip": "198.51.100.27",
        "age_minutes": 18,
        "status": "closed",
        "actions": [
            ("DIRECTORY_SCAN", 1428, 0.94, "/*", "behavior_window"),
            ("HTTP_BRUTEFORCE", 83, 0.92, "/login", "behavior_window"),
            ("XSS", 19, 0.96, "/search?q=", "detection_v2"),
            ("FILE_UPLOAD", 4, 0.97, "/api/upload", "poc_rule_engine"),
        ],
        "intent": "枚举 Web 资产并尝试获取账户后上传可执行内容",
        "conclusion": "该会话已停止活动，但动作从目录枚举推进至危险上传，应检查上传目录和认证日志。",
    },
    {
        "source_ip": "192.0.2.146",
        "age_minutes": 33,
        "status": "closed",
        "actions": [
            ("PORT_SCAN", 96, 0.88, "tcp:multiple", "tshark_syn_scan"),
            ("PATH_TRAVERSAL", 22, 0.95, "/download?file=", "detection_v2"),
            ("COMMAND_INJECTION", 7, 0.99, "/api/tools/ping", "poc_rule_engine"),
            ("WEB_SHELL", 3, 0.99, "/uploads/shell.jsp", "detection_v2"),
        ],
        "intent": "读取敏感文件并尝试获得远程命令执行能力",
        "conclusion": "链路已进入执行控制阶段，存在 WebShell 行为证据，需按严重事件立即开展主机排查。",
    },
    {
        "source_ip": "203.0.113.9",
        "age_minutes": 52,
        "status": "handled",
        "actions": [
            ("SERVICE_PROBE", 54, 0.84, "tcp:80,443", "service_probe"),
            ("GRAPHQL_PROBE", 16, 0.92, "/graphql", "detection_v2"),
            ("SSRF", 5, 0.96, "/api/fetch", "poc_rule_engine"),
            ("IP_BLOCKED", 1, 1.0, "windows-firewall", "response_action"),
        ],
        "intent": "发现 GraphQL 接口后尝试借助服务端请求访问内部资源",
        "conclusion": "该来源命中 SSRF 证据后已完成双向封禁，当前进入持续观察阶段。",
    },
    {
        "source_ip": "198.51.100.91",
        "age_minutes": 78,
        "status": "closed",
        "actions": [
            ("PORT_SCAN", 72, 0.87, "tcp:multiple", "tshark_syn_scan"),
            ("XXE", 9, 0.95, "/api/xml/import", "poc_rule_engine"),
            ("DESERIALIZATION", 3, 0.98, "/api/session/restore", "detection_v2"),
        ],
        "intent": "利用 XML 外部实体和不安全反序列化读取数据或执行代码",
        "conclusion": "三类动作构成从探测到高危执行前置条件的连续链，应核查 XML 解析器与反序列化入口。",
    },
    {
        "source_ip": "192.0.2.58",
        "age_minutes": 118,
        "status": "closed",
        "actions": [
            ("DIRECTORY_SCAN", 616, 0.90, "/*", "behavior_window"),
            ("AUTH_ABUSE", 41, 0.91, "/admin/login", "behavior_window"),
            ("SSTI", 8, 0.96, "/preview", "poc_rule_engine"),
            ("COMMAND_INJECTION", 2, 0.98, "/admin/task", "detection_v2"),
        ],
        "intent": "寻找管理入口并利用模板执行链进一步尝试命令执行",
        "conclusion": "该来源动作类型多样且阶段持续升级，虽然会话已结束，仍建议检查管理账户和模板渲染日志。",
    },
]


def clear_demo(store: MySQLSituationStore) -> Dict[str, int]:
    conn = store.connect()
    with conn.cursor() as cur:
        cur.execute("SELECT situation_id FROM attack_situations WHERE target_asset=%s", (DEMO_ASSET,))
        ids = [str(row["situation_id"]) for row in cur.fetchall()]
        if ids:
            cur.executemany("DELETE FROM situation_outbox WHERE aggregate_id=%s", [(item,) for item in ids])
        cur.execute("DELETE FROM attack_situations WHERE target_asset=%s", (DEMO_ASSET,))
        situations = int(cur.rowcount)
        cur.execute("DELETE FROM security_actions WHERE target_asset=%s", (DEMO_ASSET,))
        actions = int(cur.rowcount)
    conn.commit()
    return {"situations": situations, "actions": actions}


def build_actions(index: int, scenario: Dict[str, Any], now: datetime) -> List[SecurityAction]:
    action_specs = list(scenario["actions"])
    end_time = now - timedelta(minutes=int(scenario["age_minutes"]))
    start_time = end_time - timedelta(minutes=max(2, (len(action_specs) - 1) * 3))
    rows: List[SecurityAction] = []
    for action_index, (action_type, count, confidence, target_interface, sensor) in enumerate(action_specs, start=1):
        occurred_at = start_time + timedelta(minutes=(action_index - 1) * 3)
        rows.append(
            SecurityAction(
                action_id=f"ACT-DEMO-{index:02d}-{action_index:02d}",
                source_ip=str(scenario["source_ip"]),
                target_asset=DEMO_ASSET,
                action_type=str(action_type),
                occurred_at=occurred_at,
                last_seen_at=occurred_at + timedelta(seconds=min(90, max(1, int(count) // 3))),
                target_interface=str(target_interface),
                protocol="TCP" if str(target_interface).startswith("tcp:") else "HTTP",
                sensor=str(sensor),
                count=int(count),
                confidence=float(confidence),
                severity="critical" if float(confidence) >= 0.98 else "high",
                evidence_refs=[f"DEMO-EVIDENCE-{index:02d}-{action_index:02d}"],
                metadata={"demo": True, "scenario": index, "description": "决赛态势展示样例"},
            )
        )
    return rows


def seed_demo(store: MySQLSituationStore) -> List[Dict[str, Any]]:
    clear_demo(store)
    # MySQL DATETIME(3) stores milliseconds. Align before hashing so the
    # continuously running correlator derives the same situation ID on reload.
    current = datetime.now(timezone.utc)
    now = current.replace(microsecond=(current.microsecond // 1000) * 1000)
    result: List[Dict[str, Any]] = []
    correlator = SituationCorrelator(minimum_distinct_actions=3, window_minutes=30, inactivity_minutes=15)
    for index, scenario in enumerate(SCENARIOS, start=1):
        actions = build_actions(index, scenario, now)
        situation = correlator.correlate(actions, include_observing=False)[0]
        store.save([situation])
        if scenario["status"] != "open":
            store.update_status(situation.situation_id, str(scenario["status"]))
        report = fallback_report(situation.as_dict())
        report.update(
            {
                "narrative": (
                    f"来源 {scenario['source_ip']} 在同一关联窗口内依次出现 "
                    + "、".join(action.label for action in actions)
                    + "，动作按时间持续推进。"
                ),
                "analysis": "来源地址与目标资产一致，动作间隔均小于静默切段阈值；不同传感器证据形成连续阶段链，重复流量已按窗口聚合。",
                "conclusion": str(scenario["conclusion"]),
                "likely_intent": str(scenario["intent"]),
                "protection_measures": [
                    f"限制来源 IP {scenario['source_ip']} 访问并保留处置前证据。",
                    "核查认证、应用、数据库与主机日志，确认是否存在成功响应或持久化行为。",
                    "对暴露接口实施最小权限、速率限制和输入校验。",
                ],
                "improvement_suggestions": [
                    "将本次链路加入回归样本和处置剧本。",
                    "按攻击阶段联动网络、应用与主机侧检测规则。",
                    "持续观察来源地址及关联网段的后续活动。",
                ],
                "generated_by": "finals_demo_seed",
                "rag_hits": 3,
                "rag_refs": ["OWASP Web Security", "MITRE ATT&CK", "平台处置知识库"],
            }
        )
        store.update_ai_report(situation.situation_id, report, "complete")
        result.append(
            {
                "situation_id": situation.situation_id,
                "source_ip": scenario["source_ip"],
                "status": scenario["status"],
                "actions": len(actions),
                "risk_score": situation.risk_score,
            }
        )
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed or clear comprehensive attack-situation demo data")
    parser.add_argument("--mysql-host", default="127.0.0.1")
    parser.add_argument("--mysql-port", type=int, default=3306)
    parser.add_argument("--mysql-user", default="root")
    parser.add_argument("--mysql-password", default="123456")
    parser.add_argument("--mysql-database", default="traffic_pipeline")
    parser.add_argument("--clear", action="store_true", help="Remove demo situations and actions")
    args = parser.parse_args()

    store = MySQLSituationStore(
        MySQLSettings(args.mysql_host, args.mysql_port, args.mysql_user, args.mysql_password, args.mysql_database)
    )
    store.ensure_schema()
    try:
        if args.clear:
            print(clear_demo(store))
        else:
            for row in seed_demo(store):
                print(row)
    finally:
        store.close()


if __name__ == "__main__":
    main()
