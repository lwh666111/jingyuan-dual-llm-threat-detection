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
from typing import Any, Dict, List, Optional

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


def find_latest_completed_job(conn: Any, situation_id: str) -> Optional[Dict[str, Any]]:
    """Return the newest downloadable report even if the live chain has advanced."""
    with conn.cursor() as cur:
        cur.execute(
            """SELECT * FROM situation_professional_reports
               WHERE situation_id=%s AND status='completed' AND pdf_path IS NOT NULL
               ORDER BY completed_at DESC,created_at DESC LIMIT 1""",
            (situation_id,),
        )
        return cur.fetchone()


def get_job(conn: Any, job_id: str) -> Optional[Dict[str, Any]]:
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM situation_professional_reports WHERE job_id=%s LIMIT 1", (job_id,))
        return cur.fetchone()


def expire_stale_jobs(conn: Any, stale_seconds: int = 180) -> int:
    """Fail abandoned jobs while live workers keep their row fresh via progress heartbeats."""
    cutoff_seconds = max(60, int(stale_seconds))
    with conn.cursor() as cur:
        cur.execute(
            """UPDATE situation_professional_reports
               SET status='failed',progress=100,stage='报告任务超时，请重新生成',
                   error_message='report_task_stalled',completed_at=NOW(3)
               WHERE status IN ('queued','running')
                 AND updated_at < DATE_SUB(NOW(3), INTERVAL %s SECOND)""",
            (cutoff_seconds,),
        )
        return int(cur.rowcount or 0)


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
    # Professional reports are substantially longer than ordinary RAG requests.
    timeout_seconds = max(120, min(300, int(api_config.get("professional_report_timeout_seconds") or 240)))
    try:
        with urllib.request.urlopen(req, timeout=timeout_seconds) as response:
            data = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"百炼 HTTP {exc.code}: {exc.read().decode('utf-8', 'replace')[:500]}") from exc
    content = str((((data.get("choices") or [{}])[0].get("message") or {}).get("content") or "")).strip()
    if len(content) < 500: raise RuntimeError("专业报告内容过短，未通过质量检查")
    usage = data.get("usage") or {}
    return content, {"input": int(usage.get("prompt_tokens") or 0), "output": int(usage.get("completion_tokens") or 0)}


def _fonts() -> Dict[str, str]:
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    regular_candidates = [Path(r"C:\Windows\Fonts\msyh.ttc"), Path(r"C:\Windows\Fonts\simsun.ttc"), Path(r"C:\Windows\Fonts\simhei.ttf")]
    bold_candidates = [Path(r"C:\Windows\Fonts\msyhbd.ttc"), Path(r"C:\Windows\Fonts\simhei.ttf")]
    regular = "Helvetica"
    bold = "Helvetica-Bold"
    for path in regular_candidates:
        if path.exists():
            pdfmetrics.registerFont(TTFont("ReportCN", str(path), subfontIndex=0))
            regular = "ReportCN"
            break
    for path in bold_candidates:
        if path.exists():
            pdfmetrics.registerFont(TTFont("ReportCNBold", str(path), subfontIndex=0))
            bold = "ReportCNBold"
            break
    if regular == "ReportCN":
        pdfmetrics.registerFontFamily(
            "ReportCN", normal=regular, bold=bold,
            italic=regular, boldItalic=bold,
        )
    return {"regular": regular, "bold": bold}


def _font() -> str:
    """Backward-compatible regular font accessor used by older integrations."""
    return _fonts()["regular"]


def _action_label(value: Any) -> str:
    raw = str(value or "未知动作")
    labels = {
        "PORTSCAN": "端口扫描", "DIRSCAN": "目录扫描", "RECON": "信息探测",
        "BRUTE_FORCE": "暴力破解", "SSH_BRUTE_FORCE": "SSH 暴力破解",
        "SQL_INJECTION": "SQL 注入", "XSS": "XSS 跨站脚本", "COMMAND_INJECTION": "命令注入",
        "FILE_UPLOAD": "文件上传", "PATH_TRAVERSAL": "路径遍历", "SSRF": "SSRF",
        "XXE": "XXE", "DESERIALIZATION": "反序列化", "RCE": "远程代码执行",
    }
    return labels.get(raw.upper(), raw.replace("_", " "))


def _stage_label(value: Any) -> str:
    raw = str(value or "未归类阶段")
    labels = {
        "RECONNAISSANCE": "侦察探测", "RECON": "侦察探测", "INITIAL_ACCESS": "初始访问",
        "CREDENTIAL_ACCESS": "凭据攻击", "EXPLOITATION": "漏洞利用", "EXECUTION": "执行控制",
        "PERSISTENCE": "持久化", "LATERAL_MOVEMENT": "横向移动", "IMPACT": "影响处置",
    }
    return labels.get(raw.upper(), raw.replace("_", " "))


def _plain_markdown(text: Any) -> str:
    value = escape(_sanitize_pdf_text(text))
    value = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", value)
    value = re.sub(r"`(.+?)`", r"<font face='Courier'>\1</font>", value)
    return value


def _sanitize_pdf_text(value: Any) -> str:
    """Normalize model-authored decorations that CJK PDF fonts cannot render."""
    text = str(value if value is not None else "-")
    circled = "①②③④⑤⑥⑦⑧⑨⑩⑪⑫⑬⑭⑮⑯⑰⑱⑲⑳"
    for index, symbol in enumerate(circled, 1):
        text = text.replace(symbol, f"{index}.")
    text = re.sub(r"([0-9])\ufe0f?\u20e3", r"\1.", text)
    text = re.sub(r"[\U0001F000-\U0001FAFF]", "", text)
    text = re.sub(r"[\u2600-\u27BF\u2B00-\u2BFF]", "", text)
    text = text.replace("\ufe0f", "").replace("\u200d", "")
    return re.sub(r"[ \t]{2,}", " ", text).strip() or "-"


def _list_item_text(value: Any) -> str:
    text = _sanitize_pdf_text(value)
    return re.sub(r"^(?:\d+[.)、]\s*)+", "", text).strip() or "-"


def _time_text(value: Any) -> str:
    if value in (None, ""): return "-"
    return str(value).replace("T", " ")


def _report_title_line(text: str) -> bool:
    normalized = re.sub(r"[\s#*_`]+", "", text)
    return normalized in {"网络攻击态势感知分析报告", "专业态势感知分析报告", "专业态势感知报告"}


def render_pdf(
    output: Path,
    snapshot: Dict[str, Any],
    markdown: str,
    rag_rows: List[Dict[str, Any]],
    report_meta: Optional[Dict[str, Any]] = None,
) -> str:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import CondPageBreak, Flowable, KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    output.parent.mkdir(parents=True, exist_ok=True)
    fonts = _fonts(); font = fonts["regular"]; bold_font = fonts["bold"]
    styles = getSampleStyleSheet()
    ink = colors.HexColor("#20252B"); muted = colors.HexColor("#7B858F")
    blue = colors.HexColor("#2288F5"); pale = colors.HexColor("#F5F8FC")
    line_color = colors.HexColor("#E2E8F0")
    body = ParagraphStyle("cn", parent=styles["BodyText"], fontName=font, fontSize=9.2, leading=15.8, textColor=ink, spaceAfter=4.5, wordWrap="CJK")
    small = ParagraphStyle("small", parent=body, fontSize=7.7, leading=11.5, textColor=muted)
    h1 = ParagraphStyle("h1cn", parent=body, fontName=bold_font, fontSize=13.2, leading=19, textColor=ink, spaceBefore=11, spaceAfter=8, keepWithNext=True)
    h2 = ParagraphStyle("h2cn", parent=body, fontName=bold_font, fontSize=10.8, leading=16, textColor=ink, spaceBefore=8, spaceAfter=5, keepWithNext=False)
    h3 = ParagraphStyle("h3cn", parent=body, fontName=bold_font, fontSize=9.5, leading=14.5, textColor=ink, spaceBefore=6, spaceAfter=4, keepWithNext=False)
    title = ParagraphStyle("titlecn", parent=body, fontName=bold_font, alignment=TA_CENTER, fontSize=25, leading=34, textColor=colors.HexColor("#222222"))
    cover_brand = ParagraphStyle("coverbrand", parent=title, fontSize=18, leading=24)
    cover_meta = ParagraphStyle("covermeta", parent=body, alignment=TA_CENTER, fontSize=9.2, leading=14, textColor=colors.HexColor("#31363B"))
    bullet = ParagraphStyle("bullet", parent=body, leftIndent=8, firstLineIndent=-7, bulletIndent=0, spaceAfter=4)
    table_head = ParagraphStyle("tablehead", parent=body, fontName=bold_font, fontSize=8.4, leading=12)
    table_cell = ParagraphStyle("tablecell", parent=body, fontSize=8.2, leading=12.5)
    caption = ParagraphStyle(
        "caption", parent=small, fontSize=8.2, leading=12,
        alignment=TA_CENTER, textColor=colors.HexColor("#5E6A75"),
        spaceBefore=3, spaceAfter=6,
    )

    page_width, page_height = A4
    left = 18*mm; right = page_width - 18*mm

    def draw_cover(canvas: Any) -> None:
        canvas.saveState()
        canvas.setFillColor(colors.white); canvas.rect(0, 0, page_width, page_height, fill=1, stroke=0)
        # Pale orbit system copied from the reference's visual language.
        canvas.translate(page_width * .48, page_height * .33); canvas.rotate(13)
        orbit_colors = [colors.HexColor("#D6F5F8"), colors.HexColor("#CDEEF7"), colors.HexColor("#DDF7FA")]
        for idx, (w, h) in enumerate([(235*mm, 73*mm), (180*mm, 54*mm), (126*mm, 38*mm), (74*mm, 22*mm)]):
            canvas.setStrokeColor(orbit_colors[idx % len(orbit_colors)]); canvas.setLineWidth(0.7 if idx else 1.5)
            if idx in (1, 3): canvas.setDash(1.2, 3.2)
            else: canvas.setDash()
            canvas.ellipse(-w/2, -h/2, w/2, h/2, stroke=1, fill=0)
        canvas.setDash()
        nodes = [(-88, -3, 10), (-24, 30, 7), (39, 58, 5), (101, -28, 7), (2, -60, 9), (145, 35, 5)]
        for x, y, radius in nodes:
            canvas.setFillColor(colors.HexColor("#3F9AF5")); canvas.circle(x, y, radius, fill=1, stroke=0)
        for x, y, color in [(-61, 52, "#FFB500"), (41, -37, "#FF7078"), (124, -16, "#88DA40"), (87, -69, "#835AF2")]:
            canvas.setFillColor(colors.HexColor(color)); canvas.rect(x-2, y-2, 4, 4, fill=1, stroke=0)
        canvas.restoreState()

    def decorate(canvas: Any, doc_obj: Any) -> None:
        if doc_obj.page == 1:
            draw_cover(canvas)
            return
        canvas.saveState()
        canvas.setStrokeColor(line_color); canvas.setLineWidth(.35)
        canvas.line(left, page_height-17*mm, right, page_height-17*mm)
        canvas.line(left, 15*mm, right, 15*mm)
        canvas.setFont(font, 6.7); canvas.setFillColor(colors.HexColor("#3B4147"))
        canvas.drawString(left, page_height-12.2*mm, "靖渊智御：AI 驱动的外部 Web 威胁态势感知平台")
        canvas.drawRightString(right, page_height-12.2*mm, "Situation Report")
        canvas.setFillColor(colors.HexColor("#8A929A")); canvas.setFont(font, 6.5)
        canvas.drawString(left, 9.3*mm, "注：本报告由 AI 辅助生成，仅供安全研判与处置参考。")
        canvas.setFillColor(ink); canvas.drawRightString(right, 9.3*mm, str(doc_obj.page - 1))
        canvas.restoreState()

    class AttackChain(Flowable):
        def __init__(self, actions: List[Dict[str, Any]], width: float):
            super().__init__(); self.actions = actions[:8]; self.width = width; self.height = 24*mm
        def wrap(self, availWidth: float, availHeight: float): return min(self.width, availWidth), self.height
        def draw(self):
            c = self.canv; actions = self.actions or [{"action_type": "暂无动作", "stage": "待研判"}]
            n = len(actions); gap = 4*mm; node_w = (self.width-gap*(n-1))/n; y = 6*mm
            for i, action in enumerate(actions):
                x = i*(node_w+gap)
                if i < n-1:
                    c.setStrokeColor(colors.HexColor("#B8DDF8")); c.setLineWidth(1.2)
                    c.line(x+node_w, y+6*mm, x+node_w+gap, y+6*mm)
                    c.setFillColor(colors.HexColor("#B8DDF8")); c.wedge(x+node_w+gap-2.2*mm, y+4.8*mm, x+node_w+gap+.2*mm, y+7.2*mm, 270, 180, fill=1, stroke=0)
                c.setFillColor(colors.HexColor("#F4F8FC")); c.setStrokeColor(colors.HexColor("#D7E8F5")); c.roundRect(x, y, node_w, 12*mm, 2.2*mm, fill=1, stroke=1)
                c.setFont(bold_font, 7.2); c.setFillColor(ink)
                label = _action_label(action.get("action_type"))[:9]
                c.drawCentredString(x+node_w/2, y+6.8*mm, label)
                c.setFont(font, 5.8); c.setFillColor(muted)
                c.drawCentredString(x+node_w/2, y+3.3*mm, _stage_label(action.get("stage"))[:10])
                c.setFillColor(blue); c.circle(x+node_w/2, y+12*mm, 1.5*mm, fill=1, stroke=0)

    doc = SimpleDocTemplate(
        str(output), pagesize=A4, rightMargin=18*mm, leftMargin=18*mm,
        topMargin=22*mm, bottomMargin=19*mm, title="专业态势感知报告",
        author="靖渊智御：AI 驱动的外部 Web 威胁态势感知平台",
    )

    def p(value: Any, style: ParagraphStyle = body) -> Paragraph:
        return Paragraph(_plain_markdown(value), style)

    def make_table(rows: List[List[Any]], widths: Optional[List[float]] = None, header: bool = True, font_size: float = 8.1) -> Table:
        converted = []
        for ri, row in enumerate(rows):
            converted.append([p(cell, table_head if header and ri == 0 else table_cell) for cell in row])
        table = Table(converted, colWidths=widths, repeatRows=1 if header else 0, hAlign="LEFT")
        commands = [
            ("FONTNAME", (0,0), (-1,-1), font), ("FONTSIZE", (0,0), (-1,-1), font_size),
            ("VALIGN", (0,0), (-1,-1), "MIDDLE"), ("LEFTPADDING", (0,0), (-1,-1), 8),
            ("RIGHTPADDING", (0,0), (-1,-1), 8), ("TOPPADDING", (0,0), (-1,-1), 6.5),
            ("BOTTOMPADDING", (0,0), (-1,-1), 6.5), ("GRID", (0,0), (-1,-1), .35, line_color),
        ]
        if header: commands += [("BACKGROUND", (0,0), (-1,0), colors.HexColor("#F1F5FB")), ("FONTNAME", (0,0), (-1,0), bold_font)]
        table.setStyle(TableStyle(commands)); return table

    def table_block(label: str, table: Table, gap_after: float = 5*mm) -> List[Any]:
        """Render a centered table caption above an editable data table."""
        # Reserve enough room for the caption, header and at least two rows.
        # Unlike keepWithNext, this still lets a long table split across pages.
        return [CondPageBreak(35*mm), p(label, caption), table, Spacer(1, gap_after)]

    def figure_block(label: str, figure: Flowable, gap_after: float = 5*mm) -> List[Any]:
        """Keep a compact figure and its centered caption on the same page."""
        return [KeepTogether([figure, p(label, caption)]), Spacer(1, gap_after)]

    def card(items: List[Any], tint: Any = pale) -> Table:
        # One item per row allows long cards to split across pages instead of
        # pushing the whole card forward and leaving a mostly empty page.
        rows = [[item] for item in items] or [[p("-", body)]]
        t = Table(rows, colWidths=[doc.width], hAlign="LEFT", splitByRow=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,-1), tint), ("BOX", (0,0), (-1,-1), .25, colors.HexColor("#EDF2F7")),
            ("LEFTPADDING", (0,0), (-1,-1), 12), ("RIGHTPADDING", (0,0), (-1,-1), 12),
            ("TOPPADDING", (0,0), (-1,0), 10), ("BOTTOMPADDING", (0,-1), (-1,-1), 8),
            ("TOPPADDING", (0,1), (-1,-1), 3), ("BOTTOMPADDING", (0,0), (-1,-2), 3),
        ])); return t

    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    story: List[Any] = [
        Spacer(1, 44*mm), p("[靖渊智御]", cover_brand), Spacer(1, 3*mm),
        p("专业态势感知分析报告", title), Spacer(1, 12*mm),
        p(f"生成时间：{generated_at}", cover_meta), Spacer(1, 114*mm),
        p("来自靖渊智御：AI 驱动的外部 Web 威胁态势感知平台", ParagraphStyle("coverbottom", parent=cover_meta, fontSize=8.4, textColor=muted)),
        p("内容由 AI 基于真实传感器证据生成，请结合原始日志审慎使用", ParagraphStyle("coverbottom2", parent=cover_meta, fontSize=8.4, textColor=muted)),
        PageBreak(),
    ]

    info = [
        ["基本信息", "内容说明"],
        ["态势编号", snapshot.get("report_generated_for") or "-"],
        ["来源 IP", snapshot.get("source_ip") or "-"],
        ["目标资产", snapshot.get("target_asset") or "本机受监测服务"],
        ["风险等级", str(snapshot.get("risk_level") or "-").upper()],
        ["综合风险", f"{float(snapshot.get('risk_score') or 0):.1%}"],
        ["观测区间", f"{_time_text(snapshot.get('started_at'))} 至 {_time_text(snapshot.get('last_action_at'))}"],
        ["行为规模", f"{int(snapshot.get('distinct_action_types') or 0)} 类动作，共 {int(snapshot.get('total_action_count') or 0)} 次"],
    ]
    story += [p("一、基本信息", h1), *table_block("表1-1 基本信息", make_table(info, [55*mm, 119*mm]), 6*mm)]

    actions = list(snapshot.get("actions") or [])

    def timeline_table(action_rows: Optional[List[Dict[str, Any]]] = None) -> Table:
        rows: List[List[Any]] = [["序号", "时间", "阶段", "动作", "端口/接口", "次数", "置信度"]]
        for i, action in enumerate(action_rows if action_rows is not None else actions[:30], 1):
            confidence = action.get("confidence")
            rows.append([
                action.get("sequence_no") or i, _time_text(action.get("occurred_at")),
                _stage_label(action.get("stage")), _action_label(action.get("action_type")),
                action.get("target_port") or action.get("target_interface") or "-",
                action.get("action_count") or 1,
                f"{float(confidence):.1%}" if confidence not in (None, "") else "-",
            ])
        if len(rows) == 1: rows.append(["-", "-", "暂无", "暂无动作", "-", "0", "-"])
        return make_table(rows, [10*mm, 31*mm, 25*mm, 31*mm, 27*mm, 16*mm, 22*mm])

    def evidence_table() -> Table:
        rows: List[List[Any]] = [["证据编号", "检测来源", "对应动作", "证据状态", "说明"]]
        ev_no = 1
        for action in actions[:24]:
            refs = action.get("evidence_refs") or []
            source = action.get("sensor_type") or "融合检测"
            confidence = action.get("confidence")
            rows.append([
                f"EV-{ev_no:02d}", source, _action_label(action.get("action_type")),
                "已采集" if refs else "来源单一",
                f"动作 {int(action.get('action_count') or 1)} 次" + (f"，置信度 {float(confidence):.1%}" if confidence not in (None, "") else ""),
            ]); ev_no += 1
        if len(rows) == 1: rows.append(["EV-00", "-", "暂无", "待补充", "未提供可展示证据"])
        # Exactly match the 174 mm body width used by the following evidence table.
        return make_table(rows, [20*mm, 30*mm, 34*mm, 25*mm, 65*mm])

    def appendix_actions() -> List[Any]:
        return [timeline_table(actions)] if actions else [card([p("当前快照中未包含可列示的动作记录。", body)])]

    def appendix_evidence() -> List[Any]:
        entries: List[Any] = []
        idx = 1
        for action in actions:
            refs = action.get("evidence_refs") or []
            if not refs:
                entries.append(p(f"{idx}. [EV-{idx:02d}] {_action_label(action.get('action_type'))}：由 {action.get('sensor_type') or '融合检测'} 记录，当前未附带独立证据引用。", bullet)); idx += 1
                continue
            for ref in refs[:4]:
                entries.append(p(f"{idx}. [EV-{idx:02d}] {_action_label(action.get('action_type'))}：{ref}", bullet)); idx += 1
        return [card(entries or [p("当前快照中没有可索引的证据引用。", body)])]

    def appendix_rag() -> List[Any]:
        if not rag_rows: return [card([p("本次报告未启用或未召回 RAG 安全知识资料。", body)])]
        rows = [["序号", "知识库文档", "知识主题", "相关度"]]
        for idx, row in enumerate(rag_rows, 1):
            rows.append([idx, row.get("document_name") or "知识库文档", row.get("title_path") or "正文", f"{float(row.get('score') or 0):.1%}"])
        return [make_table(rows, [13*mm, 52*mm, 76*mm, 21*mm])]

    def appendix_generation() -> List[Any]:
        meta = dict(report_meta or {})
        rows = [
            ["生成项目", "内容说明"], ["报告生成时间", generated_at],
            ["分析对象", snapshot.get("report_generated_for") or "-"],
            ["模型名称", meta.get("model_name") or "外部大模型 API"],
            ["知识增强", "已启用" if rag_rows else "未启用或无召回结果"],
            ["证据边界", snapshot.get("evidence_boundary") or "网络侧证据不单独证明主机失陷。"],
            ["报告用途", "安全研判、事件调查与处置决策辅助"],
        ]
        return [make_table(rows, [48*mm, 126*mm])]

    inserted = {"chain": False, "timeline": False, "evidence": False, "A": False, "B": False, "C": False, "D": False}
    skip_next_table = False
    suppress_appendix_body = False
    current_chapter = "1"
    table_numbers: Dict[str, int] = {"1": 1, "4": 1, "5": 1, "6": 0, "7": 0, "A": 1, "B": 0, "C": 0, "D": 0}

    def next_table_caption(title_hint: str = "数据表") -> str:
        chapter = current_chapter
        table_numbers[chapter] = table_numbers.get(chapter, 0) + 1
        return f"表{chapter}-{table_numbers[chapter]} {title_hint}"
    lines = markdown.splitlines(); i = 0
    while i < len(lines):
        raw = lines[i]; line = raw.strip(); i += 1
        if not line: continue
        if _report_title_line(line): continue
        caption_text = re.sub(r"[《》〈〉（()）\s*_`]", "", line)
        if len(caption_text) <= 24 and caption_text.startswith("攻击链阶段") and caption_text.endswith("图"):
            continue
        heading = re.match(r"^(#{1,4})\s+(.+)$", line)
        if heading:
            level = len(heading.group(1)); text = re.sub(r"[*_`]", "", heading.group(2)).strip()
            if suppress_appendix_body and level > 2:
                continue
            suppress_appendix_body = False
            chapter_match = re.match(r"^(?:附录\s*([A-D])|([一二三四五六七])、|([1-7])(?:\.|、))", text)
            if chapter_match:
                current_chapter = chapter_match.group(1) or ({"一":"1","二":"2","三":"3","四":"4","五":"5","六":"6","七":"7"}.get(chapter_match.group(2) or "")) or chapter_match.group(3) or current_chapter
            if re.match(r"^一[、.]\s*基本信息", text):
                skip_next_table = True
                continue
            target_style = h1 if level <= 2 else h2 if level == 3 else h3
            if text.startswith("附录") and not any(x in text for x in ("附录 A", "附录 B", "附录 C", "附录 D")):
                target_style = h1
            if text.startswith("附录 A"):
                story += [p("附录 A 完整动作序列", h1), *table_block("表A-1 完整动作序列", timeline_table(actions))]; inserted["A"] = True; suppress_appendix_body = True; continue
            if text.startswith("附录 B"):
                story += [p("附录 B 关键证据索引", h1), *appendix_evidence()]; inserted["B"] = True; suppress_appendix_body = True; continue
            if text.startswith("附录 C"):
                story += [p("附录 C RAG 参考资料", h1), *table_block("表C-1 RAG 参考资料", appendix_rag()[0])]; inserted["C"] = True; suppress_appendix_body = True; continue
            if text.startswith("附录 D"):
                story += [p("附录 D 报告生成信息", h1), *table_block("表D-1 报告生成信息", appendix_generation()[0])]; inserted["D"] = True; suppress_appendix_body = True; continue
            if text.startswith(("4.1", "5.1")):
                story.append(CondPageBreak(35*mm))
            story.append(p(text, target_style))
            if text.startswith("四、") or text.startswith("4、"):
                story += figure_block("图4-1 攻击链阶段演进示意图", AttackChain(actions, doc.width), 3*mm); inserted["chain"] = True
            if text.startswith("4.1"):
                story += table_block("表4-1 攻击时间线总览", timeline_table(), 4*mm); inserted["timeline"] = True; skip_next_table = True
            if text.startswith("5.1"):
                story += table_block("表5-1 多源证据总览", evidence_table(), 6*mm); inserted["evidence"] = True
            continue
        if suppress_appendix_body:
            continue
        if line.startswith("|"):
            table_lines = [line]
            while i < len(lines) and lines[i].strip().startswith("|"):
                table_lines.append(lines[i].strip()); i += 1
            rows = []
            for table_line in table_lines:
                cells = [c.strip() for c in table_line.strip("|").split("|")]
                if all(re.fullmatch(r":?-{3,}:?", c) for c in cells): continue
                rows.append(cells)
            if skip_next_table:
                skip_next_table = False
                continue
            if rows:
                cols = max(len(r) for r in rows); widths = [doc.width/cols]*cols
                hint = "关键判断交叉验证" if current_chapter == "5" else "分析数据"
                story += table_block(next_table_caption(hint), make_table([r + [""]*(cols-len(r)) for r in rows], widths), 5*mm)
            continue
        if line.startswith(("- ", "* ")):
            bullets = [line[2:].strip()]
            while i < len(lines) and lines[i].strip().startswith(("- ", "* ")):
                bullets.append(lines[i].strip()[2:].strip()); i += 1
            bullet_items = [
                Paragraph(f"<font color='#2288F5'><b>{index}.</b></font>  " + _plain_markdown(_list_item_text(item)), bullet)
                for index, item in enumerate(bullets, 1)
            ]
            story += [card(bullet_items), Spacer(1, 2.5*mm)]
            continue
        if re.match(r"^\d+[.)]\s", line):
            story.append(p(line, bullet)); continue
        story.append(p(line, body))

    if not inserted["chain"] and actions:
        story += [p("四、攻击态势分析", h1), *figure_block("图4-1 攻击链阶段演进示意图", AttackChain(actions, doc.width))]
    if not inserted["timeline"]:
        story += [p("4.1 攻击时间线总览", h2), *table_block("表4-1 攻击时间线总览", timeline_table())]
    if not inserted["evidence"]:
        story += [p("5.1 多源证据总览", h2), *table_block("表5-1 多源证据总览", evidence_table())]
    appendix_builders = [("A", "附录 A 完整动作序列", appendix_actions), ("B", "附录 B 关键证据索引", appendix_evidence), ("C", "附录 C RAG 参考资料", appendix_rag), ("D", "附录 D 报告生成信息", appendix_generation)]
    missing = [entry for entry in appendix_builders if not inserted[entry[0]]]
    if missing:
        for _, heading_text, builder in missing:
            appendix = heading_text.split()[1] if heading_text.startswith("附录 ") else current_chapter
            built = builder()
            if built and isinstance(built[0], Table):
                story += [p(heading_text, h1), *table_block(f"表{appendix}-1 {heading_text.split(' ', 2)[-1]}", built[0])]
            else:
                story += [p(heading_text, h1), *built]
    story += [Spacer(1, 7*mm), card([
        p("感谢使用靖渊智御外部 Web 威胁态势感知分析系统。", h3),
        p("本报告根据系统采集的网络安全事件、检测模型结果、规则证据、行为信息及安全知识资料综合生成，仅作为安全研判、事件调查与防护决策的辅助依据。", small),
    ], colors.HexColor("#F3F6FC"))]
    doc.build(story, onFirstPage=decorate, onLaterPages=decorate)
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
            progress_stop = threading.Event()

            def report_progress() -> None:
                for progress, stage in (
                    (43, "外部模型正在分析攻击链"),
                    (52, "外部模型正在核验证据边界"),
                    (61, "外部模型正在生成处置建议"),
                    (70, "外部模型正在完成专业报告"),
                ):
                    if progress_stop.wait(10):
                        return
                    update_job(self.mysql_conf, job_id, progress, stage)

            ticker = threading.Thread(target=report_progress, daemon=True, name=f"professional-progress-{job_id[-6:]}")
            ticker.start()
            try:
                markdown, usage = call_bailian(api, model, prompt, snapshot, rag_rows)
            finally:
                progress_stop.set()
                ticker.join(timeout=1)
            update_job(self.mysql_conf, job_id, 82, "正在排版并校验 PDF", model_name=model, report_markdown=markdown, input_tokens=usage["input"], output_tokens=usage["output"])
            output = self.report_dir / f"{job['situation_id']}_{job['sequence_hash']}.pdf"
            digest = render_pdf(
                output, snapshot, markdown, rag_rows,
                report_meta={"model_name": model, "input_tokens": usage["input"], "output_tokens": usage["output"]},
            )
            update_job(self.mysql_conf, job_id, 100, "专业态势报告已生成", status="completed", pdf_path=str(output), pdf_sha256=digest, completed_at=datetime.now())
        except Exception as exc:
            update_job(self.mysql_conf, job_id, 100, "报告生成失败", status="failed", error_message=f"{type(exc).__name__}: {exc}"[:2000], completed_at=datetime.now())
        finally:
            with self._lock: self._active.discard(job_id)
