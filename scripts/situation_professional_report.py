from __future__ import annotations

import hashlib
import json
import re
import threading
import urllib.error
import urllib.request
import uuid
from xml.sax.saxutils import escape
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import pymysql
from pymysql.cursors import DictCursor

try:
    from rag_service import hybrid_search, list_kbs, load_api_config, mysql_connect
    from situation_store import MySQLSettings, MySQLSituationStore
except ImportError:  # Support package-style imports in tests and maintenance tools.
    from scripts.rag_service import hybrid_search, list_kbs, load_api_config, mysql_connect
    from scripts.situation_store import MySQLSettings, MySQLSituationStore


REPORT_SCHEMA = """
CREATE TABLE IF NOT EXISTS situation_professional_reports (
  job_id VARCHAR(40) PRIMARY KEY,
  situation_id VARCHAR(64) NOT NULL,
  sequence_hash VARCHAR(64) NOT NULL,
  status VARCHAR(24) NOT NULL DEFAULT 'queued',
  progress INT NOT NULL DEFAULT 0,
  stage VARCHAR(80) NOT NULL DEFAULT '任务已创建',
  model_name VARCHAR(80) NULL,
  snapshot_json LONGTEXT NULL,
  rag_references_json LONGTEXT NULL,
  report_markdown LONGTEXT NULL,
  pdf_path TEXT NULL,
  pdf_sha256 VARCHAR(64) NULL,
  input_tokens INT NOT NULL DEFAULT 0,
  output_tokens INT NOT NULL DEFAULT 0,
  error_message TEXT NULL,
  requested_by VARCHAR(80) NOT NULL,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  started_at DATETIME(3) NULL,
  completed_at DATETIME(3) NULL,
  updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  UNIQUE KEY uniq_situation_revision (situation_id, sequence_hash),
  KEY idx_report_status (status, updated_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
"""


def connect(conf: Dict[str, Any], autocommit: bool = False):
    return pymysql.connect(
        host=conf["host"], port=int(conf["port"]), user=conf["user"], password=conf["password"],
        database=conf["database"], charset="utf8mb4", cursorclass=DictCursor, autocommit=autocommit,
    )


def ensure_schema(conn: Any) -> None:
    with conn.cursor() as cur:
        cur.execute(REPORT_SCHEMA)
        cur.execute("UPDATE situation_professional_reports SET status='failed',stage='服务重启，任务已中断',error_message='service_restarted' WHERE status IN ('queued','running')")
    conn.commit()


def public_job(row: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not row:
        return None
    return {
        "job_id": row.get("job_id"), "situation_id": row.get("situation_id"),
        "sequence_hash": row.get("sequence_hash"), "status": row.get("status"),
        "progress": int(row.get("progress") or 0), "stage": row.get("stage"),
        "model_name": row.get("model_name"), "input_tokens": int(row.get("input_tokens") or 0),
        "output_tokens": int(row.get("output_tokens") or 0), "error_message": row.get("error_message"),
        "created_at": row.get("created_at"), "started_at": row.get("started_at"),
        "completed_at": row.get("completed_at"), "updated_at": row.get("updated_at"),
        "ready": row.get("status") == "completed" and bool(row.get("pdf_path")),
    }


def find_job(conn: Any, situation_id: str, sequence_hash: str = "") -> Optional[Dict[str, Any]]:
    with conn.cursor() as cur:
        if sequence_hash:
            cur.execute("SELECT * FROM situation_professional_reports WHERE situation_id=%s AND sequence_hash=%s LIMIT 1", (situation_id, sequence_hash))
        else:
            cur.execute("SELECT * FROM situation_professional_reports WHERE situation_id=%s ORDER BY created_at DESC LIMIT 1", (situation_id,))
        return cur.fetchone()


def get_job(conn: Any, job_id: str) -> Optional[Dict[str, Any]]:
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM situation_professional_reports WHERE job_id=%s LIMIT 1", (job_id,))
        return cur.fetchone()


def create_job(conn: Any, situation: Dict[str, Any], username: str) -> Dict[str, Any]:
    situation_id = str(situation["situation_id"])
    sequence_hash = str(situation.get("sequence_hash") or "")
    existing = find_job(conn, situation_id, sequence_hash)
    if existing and existing.get("status") != "failed":
        return existing
    job_id = f"SPR-{uuid.uuid4().hex[:24].upper()}"
    if existing:
        with conn.cursor() as cur:
            cur.execute(
                """UPDATE situation_professional_reports SET job_id=%s,status='queued',progress=2,stage='任务已创建',
                   error_message=NULL,requested_by=%s,started_at=NULL,completed_at=NULL,pdf_path=NULL WHERE situation_id=%s AND sequence_hash=%s""",
                (job_id, username, situation_id, sequence_hash),
            )
    else:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO situation_professional_reports(job_id,situation_id,sequence_hash,status,progress,stage,requested_by)
                   VALUES(%s,%s,%s,'queued',2,'任务已创建',%s)""",
                (job_id, situation_id, sequence_hash, username),
            )
    conn.commit()
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM situation_professional_reports WHERE job_id=%s", (job_id,))
        return cur.fetchone()


def update_job(conf: Dict[str, Any], job_id: str, progress: int, stage: str, **fields: Any) -> None:
    allowed = {"status", "model_name", "snapshot_json", "rag_references_json", "report_markdown", "pdf_path", "pdf_sha256", "input_tokens", "output_tokens", "error_message", "started_at", "completed_at"}
    values: List[Any] = [max(0, min(100, int(progress))), stage[:80]]
    sets = ["progress=%s", "stage=%s"]
    for key, value in fields.items():
        if key in allowed:
            sets.append(f"{key}=%s")
            values.append(value)
    values.append(job_id)
    with connect(conf, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(f"UPDATE situation_professional_reports SET {','.join(sets)} WHERE job_id=%s", tuple(values))


def json_safe(value: Any) -> Any:
    if isinstance(value, dict): return {str(k): json_safe(v) for k, v in value.items()}
    if isinstance(value, list): return [json_safe(v) for v in value]
    if isinstance(value, (datetime,)): return value.isoformat(timespec="milliseconds")
    return value


def build_snapshot(situation: Dict[str, Any]) -> Dict[str, Any]:
    report = situation.get("ai_report") or {}
    actions = []
    for source in (situation.get("actions") or [])[:120]:
        actions.append({
            "sequence_no": source.get("sequence_no"), "action_id": source.get("action_id"),
            "action_type": source.get("action_type"), "stage": source.get("stage"),
            "sensor_type": source.get("sensor_type"), "occurred_at": source.get("occurred_at"),
            "last_seen_at": source.get("last_seen_at"), "action_count": source.get("action_count"),
            "confidence": source.get("confidence"), "severity": source.get("severity"),
            "target_port": source.get("target_port"), "target_interface": source.get("target_interface"),
            "evidence_refs": source.get("evidence_refs") or [],
        })
    return json_safe({
        "schema_version": "1.0", "report_generated_for": situation.get("situation_id"),
        "source_ip": situation.get("source_ip"), "target_asset": situation.get("target_asset"),
        "started_at": situation.get("started_at"), "last_action_at": situation.get("last_action_at"),
        "status": situation.get("status"), "risk_score": situation.get("risk_score"),
        "risk_level": situation.get("risk_level"), "distinct_action_types": situation.get("distinct_action_types"),
        "total_action_count": situation.get("total_action_count"), "current_stage": situation.get("current_stage"),
        "actions": actions, "existing_ai_assessment": report,
        "evidence_boundary": "网络侧证据证明请求或连接行为发生，不单独证明命令执行、数据泄露或主机失陷。",
    })


def retrieve_context(mysql_conf: Dict[str, Any], data_dir: Path, api_path: Path, snapshot: Dict[str, Any]) -> List[Dict[str, Any]]:
    api_config = load_api_config(api_path)
    conn = mysql_connect(mysql_conf, autocommit=True)
    try:
        bases = list_kbs(conn, include_disabled=False)
        if not bases: return []
        query = " ".join([str(snapshot.get("current_stage") or ""), *[str(a.get("action_type") or "") for a in snapshot.get("actions") or []], "应急响应 防护 加固 证据边界"])
        result = hybrid_search(conn, data_dir, api_config, int(bases[0]["id"]), query, "professional-report", save_test=False)
        return list(result.get("items") or [])[:6]
    finally:
        conn.close()


def call_bailian(api_config: Dict[str, Any], model: str, system_prompt: str, snapshot: Dict[str, Any], rag_rows: List[Dict[str, Any]]) -> tuple[str, Dict[str, int]]:
    references = [{"document": x.get("document_name"), "title": x.get("title_path"), "content": str(x.get("content") or "")[:1800], "score": x.get("score")} for x in rag_rows]
    user_content = "请严格依据以下不可变事件快照和RAG参考资料生成最终Markdown报告。不得把攻击尝试写成攻击成功；证据不足时必须明确写明。\n\n事件快照：\n" + json.dumps(snapshot, ensure_ascii=False) + "\n\nRAG参考资料：\n" + json.dumps(references, ensure_ascii=False)
    payload = {"model": model, "messages": [{"role": "system", "content": system_prompt}, {"role": "user", "content": user_content}], "temperature": 0.2, "stream": False}
    req = urllib.request.Request(
        f"{api_config['base_url']}/chat/completions", data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={"Authorization": f"Bearer {api_config['api_key']}", "Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=max(180, int(api_config.get("timeout_seconds") or 90))) as response:
            data = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"百炼 HTTP {exc.code}: {exc.read().decode('utf-8', 'replace')[:500]}") from exc
    content = str((((data.get("choices") or [{}])[0].get("message") or {}).get("content") or "")).strip()
    if len(content) < 500: raise RuntimeError("专业报告内容过短，未通过质量检查")
    usage = data.get("usage") or {}
    return content, {"input": int(usage.get("prompt_tokens") or 0), "output": int(usage.get("completion_tokens") or 0)}


def _font() -> str:
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    candidates = [Path(r"C:\Windows\Fonts\msyh.ttc"), Path(r"C:\Windows\Fonts\simhei.ttf"), Path(r"C:\Windows\Fonts\simsun.ttc")]
    for path in candidates:
        if path.exists():
            pdfmetrics.registerFont(TTFont("ReportCN", str(path), subfontIndex=0))
            return "ReportCN"
    return "Helvetica"


def render_pdf(output: Path, snapshot: Dict[str, Any], markdown: str, rag_rows: List[Dict[str, Any]]) -> str:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    output.parent.mkdir(parents=True, exist_ok=True)
    font = _font(); styles = getSampleStyleSheet()
    body = ParagraphStyle("cn", parent=styles["BodyText"], fontName=font, fontSize=9.5, leading=16, textColor=colors.HexColor("#263442"), spaceAfter=6)
    h1 = ParagraphStyle("h1cn", parent=body, fontSize=18, leading=24, textColor=colors.HexColor("#13293D"), spaceBefore=12, spaceAfter=10)
    h2 = ParagraphStyle("h2cn", parent=body, fontSize=13, leading=19, textColor=colors.HexColor("#176B87"), spaceBefore=9, spaceAfter=6)
    h3 = ParagraphStyle("h3cn", parent=body, fontSize=11, leading=17, textColor=colors.HexColor("#245B76"), spaceBefore=7, spaceAfter=4)
    title = ParagraphStyle("titlecn", parent=body, alignment=TA_CENTER, fontSize=25, leading=34, textColor=colors.HexColor("#102A43"))
    def footer(canvas, doc):
        canvas.saveState(); canvas.setStrokeColor(colors.HexColor("#C9DCE8")); canvas.line(22*mm, 16*mm, 188*mm, 16*mm)
        canvas.setFont(font, 7.5); canvas.setFillColor(colors.HexColor("#71879A")); canvas.drawString(22*mm, 10*mm, "智御态势 · 专业态势感知报告")
        canvas.drawRightString(188*mm, 10*mm, f"{doc.page}"); canvas.restoreState()
    doc = SimpleDocTemplate(str(output), pagesize=A4, rightMargin=22*mm, leftMargin=22*mm, topMargin=22*mm, bottomMargin=20*mm, title="专业态势感知报告")
    safe = lambda value: escape(str(value if value is not None else "-"))
    story: List[Any] = [Spacer(1, 42*mm), Paragraph("专业态势感知分析报告", title), Spacer(1, 12*mm), Paragraph(f"态势编号：{safe(snapshot.get('report_generated_for','-'))}", ParagraphStyle("center", parent=body, alignment=TA_CENTER)), Spacer(1, 4*mm), Paragraph(f"生成时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ParagraphStyle("center2", parent=body, alignment=TA_CENTER)), PageBreak()]
    info = [["来源 IP", snapshot.get("source_ip") or "-", "目标资产", snapshot.get("target_asset") or "-"], ["风险等级", snapshot.get("risk_level") or "-", "风险评分", f"{float(snapshot.get('risk_score') or 0):.1%}"], ["起始时间", snapshot.get("started_at") or "-", "最近动作", snapshot.get("last_action_at") or "-"], ["动作种类", snapshot.get("distinct_action_types") or 0, "累计频次", snapshot.get("total_action_count") or 0]]
    table = Table(info, colWidths=[28*mm, 54*mm, 28*mm, 54*mm])
    table.setStyle(TableStyle([("FONTNAME",(0,0),(-1,-1),font),("FONTSIZE",(0,0),(-1,-1),8.5),("BACKGROUND",(0,0),(0,-1),colors.HexColor("#EAF4FA")),("BACKGROUND",(2,0),(2,-1),colors.HexColor("#EAF4FA")),("GRID",(0,0),(-1,-1),.4,colors.HexColor("#BCD2DF")),("VALIGN",(0,0),(-1,-1),"MIDDLE"),("PADDING",(0,0),(-1,-1),7)])); story += [Paragraph("一、基本信息", h1), table, Spacer(1, 8*mm)]
    for raw in markdown.splitlines():
        line = raw.strip()
        if not line: continue
        line = re.sub(r"[*_`]", "", line)
        # The basic-information table is rendered above from immutable data.
        # Ignore the model's placeholder heading so the chapter is not duplicated.
        if re.fullmatch(r"#{1,4}\s*一[、.]\s*基本信息", line):
            continue
        if line.startswith("#### "): story.append(Paragraph(safe(line[5:]), h3))
        elif line.startswith("### "): story.append(Paragraph(safe(line[4:]), h2))
        elif line.startswith("## "): story.append(Paragraph(safe(line[3:]), h1))
        elif line.startswith("# "): story.append(Paragraph(safe(line[2:]), h1))
        elif line.startswith(("- ", "* ")): story.append(Paragraph("• " + safe(line[2:]), body))
        elif re.match(r"^\d+[.)]\s", line): story.append(Paragraph(safe(line), body))
        elif not line.startswith("|"): story.append(Paragraph(safe(line), body))
    if rag_rows:
        story += [PageBreak(), Paragraph("附录 C RAG 参考资料", h1)]
        for idx, row in enumerate(rag_rows, 1): story.append(Paragraph(safe(f"{idx}. {row.get('document_name') or '知识库文档'} - {row.get('title_path') or '正文'}（相关度 {float(row.get('score') or 0):.1%}）"), body))
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return hashlib.sha256(output.read_bytes()).hexdigest()


class ProfessionalReportManager:
    def __init__(self, mysql_conf: Dict[str, Any], report_dir: Path, prompt_path: Path, rag_data_dir: Path, rag_api_path: Path):
        self.mysql_conf = dict(mysql_conf); self.report_dir = report_dir; self.prompt_path = prompt_path
        self.rag_data_dir = rag_data_dir; self.rag_api_path = rag_api_path; self._lock = threading.Lock(); self._active: set[str] = set()

    def start(self, job_id: str) -> None:
        with self._lock:
            if job_id in self._active: return
            self._active.add(job_id)
        threading.Thread(target=self._run, args=(job_id,), daemon=True, name=f"professional-report-{job_id[-6:]}").start()

    def _run(self, job_id: str) -> None:
        try:
            update_job(self.mysql_conf, job_id, 8, "正在整理态势证据", status="running", started_at=datetime.now(), error_message=None)
            with connect(self.mysql_conf, autocommit=True) as conn:
                with conn.cursor() as cur: cur.execute("SELECT * FROM situation_professional_reports WHERE job_id=%s", (job_id,)); job = cur.fetchone()
            store = MySQLSituationStore(MySQLSettings(**self.mysql_conf)); situation = store.get_situation(str(job["situation_id"])); store.close()
            if not situation: raise RuntimeError("态势不存在或已被删除")
            snapshot = build_snapshot(situation)
            update_job(self.mysql_conf, job_id, 20, "正在检索安全知识库", snapshot_json=json.dumps(snapshot, ensure_ascii=False))
            try: rag_rows = retrieve_context(self.mysql_conf, self.rag_data_dir, self.rag_api_path, snapshot)
            except Exception: rag_rows = []
            update_job(self.mysql_conf, job_id, 35, "正在调用外部模型生成专业分析", rag_references_json=json.dumps(rag_rows, ensure_ascii=False))
            api = load_api_config(self.rag_api_path); config_payload = json.loads(self.rag_api_path.read_text(encoding="utf-8-sig")) if self.rag_api_path.exists() else {}
            model = str(config_payload.get("report_model") or "qwen-plus")
            prompt = self.prompt_path.read_text(encoding="utf-8-sig")
            markdown, usage = call_bailian(api, model, prompt, snapshot, rag_rows)
            update_job(self.mysql_conf, job_id, 82, "正在排版并校验 PDF", model_name=model, report_markdown=markdown, input_tokens=usage["input"], output_tokens=usage["output"])
            output = self.report_dir / f"{job['situation_id']}_{job['sequence_hash']}.pdf"
            digest = render_pdf(output, snapshot, markdown, rag_rows)
            update_job(self.mysql_conf, job_id, 100, "专业态势报告已生成", status="completed", pdf_path=str(output), pdf_sha256=digest, completed_at=datetime.now())
        except Exception as exc:
            update_job(self.mysql_conf, job_id, 100, "报告生成失败", status="failed", error_message=f"{type(exc).__name__}: {exc}"[:2000], completed_at=datetime.now())
        finally:
            with self._lock: self._active.discard(job_id)
