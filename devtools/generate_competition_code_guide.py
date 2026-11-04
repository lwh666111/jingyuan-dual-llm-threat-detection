from __future__ import annotations

import ast
import io
import re
import shutil
import tokenize
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIR = ROOT / "scripts"
OUTPUT_DIR = ROOT / "docs" / "比赛答辩_scripts代码速查"
SUPPORTED_SUFFIXES = {".py", ".ps1", ".bat", ".js"}


SCRIPT_PURPOSES = {
    "dashboard_api_server.py": "Flask 后端主服务：JWT 鉴权、用户与管理员接口、态势大屏、RAG 管理、自动防御、报告任务和数据库查询。",
    "capture_http_request_batches.py": "调用 TShark 实时抓取 HTTP 流量，解析请求/响应并触发快速防御与检测流水线。",
    "security_detection_v2.py": "新架构融合检测核心：Payload 模型、POC 规则、行为窗口和上下文证据融合。",
    "web_attack_rules.py": "Web 攻击 POC 规则库，识别 SQL 注入、XSS、命令注入、路径遍历、SSRF、XXE 等典型载荷。",
    "fast_defense.py": "自动防御快速路径：匹配高确定性规则并调用防火墙控制，缩短封禁时间。",
    "firewall_control.py": "Windows 防火墙双向封禁与解封实现，维护安全操作记录。",
    "llm_analyzer_daemon.py": "大模型研判守护进程：消费候选事件、检索 RAG、调用本地或外部模型并写回结构化结论。",
    "raw_llm_review.py": "RAW 候选事件并发复核、DeepSeek/OpenAI 兼容 API 调用、缓存与任务状态管理。",
    "rag_service.py": "RAG 知识库核心：文档解析、切片、向量化、召回、重排、阈值判断和回归评估。",
    "build_rag_db.py": "从种子知识文件构建兼容的本地 RAG 索引。",
    "seed_authoritative_rag.py": "导入 OWASP 等权威安全知识，建立可用于研判的初始知识库。",
    "situation_core.py": "按来源、时间和攻击阶段关联事件，形成单 IP 攻击态势。",
    "situation_cluster.py": "跨 IP 聚类与多代理协同态势识别。",
    "situation_store.py": "态势、动作、证据、报告和队列数据的 MySQL 持久化访问层。",
    "situation_ai.py": "调用外部 API 生成普通 AI 态势报告并校验结构化结果。",
    "situation_ai_daemon.py": "消费普通态势报告队列，处理优先级、重试、超时和状态回写。",
    "situation_professional_report.py": "生成专业态势报告及 PDF/Word 文档，负责模板、表格、图形和版式。",
    "situation_supervisor.py": "态势子服务监护器，启动并检查端口扫描、态势聚合和 AI 报告进程。",
    "situation_daemon.py": "周期性读取攻击事件并生成、更新攻击者态势。",
    "port_scan_sensor.py": "从 TCP SYN/连接行为中识别端口扫描并写入行为证据。",
    "ssh_bruteforce_monitor.py": "读取 Windows SSH 登录失败日志，按时间窗聚合 SSH 暴力破解。",
    "sync_raw_http_logs.py": "将原始 HTTP 流量同步到 MySQL，供新检测链路和审计回溯使用。",
    "result_db_daemon.py": "持续扫描 result 目录并把请求、响应、分析结论同步到 MySQL。",
    "build_result_db.py": "创建结果数据库表结构并导入历史 result 文件。",
    "pipeline_events.py": "提供轻量事件通知，减少文件轮询造成的流水线等待。",
    "run_demo_daemon.py": "监控 input 目录并调度小模型检测工作流。",
    "demo_workflow.py": "执行旧模型兼容筛选、候选导出和检测结果组织。",
    "target_multivuln_lab.py": "4000 端口多漏洞靶场，提供信息收集、经典漏洞、Nday 和模拟 0day 测试入口。",
    "auto_defense_daemon.py": "根据已确认攻击事件执行自动封禁，并处理配置开关与重复操作。",
    "train_payload_model_v2.py": "训练 Payload 文本/特征模型并保存模型与评估结果。",
    "train_behavior_model_v2.py": "训练扫描、爆破等行为窗口模型。",
    "train_synthetic_web_mlp.py": "生成与训练兼容旧链路的 Web 流量 MLP 模型。",
    "evaluate_detection_v2.py": "评估新检测架构的准确率、精确率、召回率和 F1。",
    "iterative_threshold_tuning.py": "迭代实验不同阈值，比较正常/攻击流量并输出调参结论。",
    "real_capture_threshold_compare.py": "使用真实抓包数据比较阈值效果。",
    "sync_detection_v2_db.py": "将新架构候选、模型预测、POC 命中和行为窗口同步到数据库。",
    "situation_neo4j_sync.py": "可选 Neo4j 图数据同步，实现攻击者、动作和资产关系映射。",
}


ANSWER_TOPICS = {
    "抓包与网卡选择": ["capture_http_request_batches.py", "tshark", "interface"],
    "三个小模型与融合评分": ["security_detection_v2.py", "payload", "behavior", "fusion"],
    "POC 规则引擎": ["web_attack_rules.py", "poc", "rule"],
    "大模型最终研判": ["llm_analyzer_daemon.py", "raw_llm_review.py", "review"],
    "RAG 文档切片与向量召回": ["rag_service.py", "embedding", "chunk", "retrieve"],
    "DeepSeek/外部 API 并发": ["raw_llm_review.py", "ThreadPoolExecutor", "compatible-mode"],
    "自动防御与真实封禁": ["fast_defense.py", "firewall_control.py", "block"],
    "态势关联与多代理聚合": ["situation_core.py", "situation_cluster.py", "cluster"],
    "普通与专业态势报告": ["situation_ai.py", "situation_professional_report.py", "report"],
    "MySQL 数据留痕": ["build_result_db.py", "result_db_daemon.py", "CREATE TABLE"],
    "4000 靶场与指纹快速路径": ["target_multivuln_lab.py", "fingerprint", "4000"],
    "Flask 接口与 JWT 权限": ["dashboard_api_server.py", "@app.route", "require_roles"],
}


TOKEN_LABELS = {
    "get": "读取",
    "load": "加载",
    "read": "读取",
    "fetch": "获取",
    "list": "列出",
    "create": "创建",
    "build": "构建",
    "update": "更新",
    "delete": "删除",
    "remove": "移除",
    "save": "保存",
    "write": "写入",
    "sync": "同步",
    "run": "运行",
    "start": "启动",
    "stop": "停止",
    "check": "检查",
    "validate": "校验",
    "normalize": "标准化",
    "parse": "解析",
    "format": "格式化",
    "render": "渲染",
    "resolve": "解析并确定",
    "aggregate": "聚合",
    "detect": "检测",
    "evaluate": "评估",
    "train": "训练",
    "predict": "预测",
    "retrieve": "召回",
    "rerank": "重排",
    "embed": "向量化",
    "block": "封禁",
    "unblock": "解封",
    "login": "登录",
    "register": "注册",
    "report": "报告",
    "source": "来源",
    "event": "事件",
    "events": "事件",
    "attack": "攻击",
    "situation": "态势",
    "config": "配置",
    "status": "状态",
    "result": "结果",
    "items": "数据项",
    "rows": "数据库记录",
    "model": "模型",
    "database": "数据库",
    "db": "数据库",
    "api": "接口",
}


@dataclass(frozen=True)
class Symbol:
    file: str
    line: int
    end_line: int
    kind: str
    name: str
    signature: str
    parent: str = ""


def iter_source_files() -> list[Path]:
    return sorted(
        path
        for path in SOURCE_DIR.rglob("*")
        if path.is_file() and path.suffix.lower() in SUPPORTED_SUFFIXES
    )


def humanize_name(name: str) -> str:
    words = [word for word in re.split(r"[_\-]+", name.strip("_")) if word]
    translated = [TOKEN_LABELS.get(word.lower(), word) for word in words]
    return "".join(translated) or name


def collect_python_metadata(path: Path, text: str) -> tuple[list[Symbol], dict[int, str], set[int]]:
    symbols: list[Symbol] = []
    line_context: dict[int, str] = {}
    string_lines: set[int] = set()
    try:
        for token in tokenize.generate_tokens(io.StringIO(text).readline):
            if token.type == tokenize.STRING and token.end[0] > token.start[0]:
                string_lines.update(range(token.start[0], token.end[0] + 1))
    except (tokenize.TokenError, IndentationError):
        pass
    try:
        tree = ast.parse(text, filename=str(path))
    except SyntaxError:
        return symbols, line_context, string_lines

    parents: dict[ast.AST, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node

    for node in ast.walk(tree):
        if not isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        kind = "类" if isinstance(node, ast.ClassDef) else "异步函数" if isinstance(node, ast.AsyncFunctionDef) else "函数"
        parent = parents.get(node)
        parent_name = parent.name if isinstance(parent, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) else ""
        source_line = text.splitlines()[node.lineno - 1].strip() if node.lineno <= len(text.splitlines()) else node.name
        symbol = Symbol(
            file=str(path.relative_to(ROOT)).replace("\\", "/"),
            line=node.lineno,
            end_line=getattr(node, "end_lineno", node.lineno),
            kind=kind,
            name=node.name,
            signature=source_line,
            parent=parent_name,
        )
        symbols.append(symbol)
        context = f"{kind} {node.name}"
        for line_no in range(symbol.line, symbol.end_line + 1):
            current = line_context.get(line_no)
            if current is None or (symbol.end_line - symbol.line) < _context_span(symbols, current):
                line_context[line_no] = context
    return sorted(symbols, key=lambda item: item.line), line_context, string_lines


def _context_span(symbols: Iterable[Symbol], context: str) -> int:
    name = context.split(" ", 1)[-1]
    matching = [item.end_line - item.line for item in symbols if item.name == name]
    return min(matching, default=10**9)


def extract_route(line: str) -> str:
    match = re.search(r"@(?:app|bp)\.route\((.+)", line)
    return match.group(1).rstrip(")") if match else ""


def describe_line(line: str, line_no: int, suffix: str, context: str, string_lines: set[int]) -> str:
    stripped = line.strip()
    where = f"，当前位于{context}" if context else ""
    if not stripped:
        return "分隔相邻逻辑块，便于阅读和定位。"
    if stripped.startswith("#!"):
        return "声明脚本解释器或运行环境。"
    if re.match(r"^#.*coding[:=]", stripped):
        return "声明源码字符编码，确保中文内容正常解析。"
    if stripped.startswith(("#", "//", "REM ", "rem ", "::")):
        return f"源码原注释：{stripped.lstrip('#/ :')}"
    if line_no in string_lines:
        upper = stripped.upper()
        if any(keyword in upper for keyword in ("SELECT ", "INSERT ", "UPDATE ", "DELETE ", "CREATE TABLE", "ALTER TABLE")):
            return f"定义或拼接 MySQL 语句，用于读取或写入业务数据{where}。"
        if any(tag in stripped.lower() for tag in ("<html", "<div", "<form", "<script", "<style")):
            return f"定义靶场或报告中的 HTML 页面片段{where}。"
        return f"定义多行文本、提示词、模板或 SQL 片段{where}。"
    if stripped.startswith(("from ", "import ")):
        return f"导入后续逻辑所需的模块、类或函数：`{stripped}`。"
    if stripped.startswith("@app.route") or stripped.startswith("@bp.route"):
        route = extract_route(stripped)
        return f"注册 Flask HTTP 接口 {route}，下一函数负责处理该请求。"
    if stripped.startswith("@require_roles"):
        return "限制接口访问角色，JWT 用户必须具备指定权限。"
    if stripped.startswith("@"):
        return f"应用装饰器 `{stripped}`，为下一定义附加权限、缓存或注册行为。"
    match = re.match(r"(?:async\s+)?def\s+([A-Za-z_]\w*)", stripped)
    if match:
        name = match.group(1)
        return f"定义{humanize_name(name)}函数 `{name}`，封装可复用业务逻辑。"
    match = re.match(r"class\s+([A-Za-z_]\w*)", stripped)
    if match:
        return f"定义类 `{match.group(1)}`，集中保存相关状态与操作。"
    if stripped.startswith("if ") or stripped.startswith("if("):
        return f"判断条件是否成立，成立时进入对应处理分支{where}。"
    if stripped.startswith("elif "):
        return f"当前一条件未命中时继续判断另一条件{where}。"
    if stripped.startswith("else"):
        return f"处理前述条件均未命中的情况{where}。"
    if stripped.startswith("for "):
        return f"遍历集合中的数据项并逐项处理{where}。"
    if stripped.startswith("while "):
        return f"在条件成立期间循环执行，常用于守护进程轮询{where}。"
    if stripped == "try:" or stripped.startswith("try:"):
        return f"开始受保护操作，异常会交给后续分支处理{where}。"
    if stripped.startswith("except"):
        return f"捕获异常，避免单次错误导致整个服务退出{where}。"
    if stripped.startswith("finally"):
        return f"无论成功或异常都执行资源清理{where}。"
    if stripped.startswith("with "):
        return f"通过上下文管理器安全打开资源，并在结束后自动释放{where}。"
    if stripped.startswith("return"):
        return f"结束当前函数并把结果返回给调用方{where}。"
    if stripped.startswith(("raise ", "raise(")):
        return f"主动抛出异常，阻止无效或危险状态继续执行{where}。"
    if stripped.startswith(("break", "continue", "pass")):
        return f"控制当前循环或占位分支的执行流程{where}。"
    if "add_argument(" in stripped:
        return "声明一个命令行启动参数，允许部署时覆盖默认配置。"
    if ".execute(" in stripped or stripped.startswith(("SELECT ", "INSERT ", "UPDATE ", "DELETE ")):
        return f"向 MySQL 执行参数化查询或结构维护语句{where}。"
    if any(marker in stripped for marker in ("model.predict", "predict_proba", "torch.no_grad", ".forward(")):
        return f"执行小模型推理并取得预测分数{where}。"
    if any(marker in stripped.lower() for marker in ("embedding", "vector", "cosine", "rerank")):
        return f"处理向量、相似度或重排结果，属于 RAG 检索链路{where}。"
    if any(marker in stripped.lower() for marker in ("requests.post", "urlopen(", "openai", "chat/completions")):
        return f"调用外部 HTTP/大模型 API，并等待远端返回结果{where}。"
    if any(marker in stripped for marker in ("log(", "logger.", "print(")):
        return f"记录运行状态或诊断信息，便于日志排障{where}。"
    if ".append(" in stripped or ".extend(" in stripped or ".add(" in stripped:
        return f"把当前结果加入集合，供后续聚合、排序或返回{where}。"
    if stripped.startswith(("}", "]", ")")) or stripped in {"},", "],", "),"}:
        return f"结束前面开始的字典、列表、参数或表达式结构{where}。"
    assignment = re.match(r"(?:self\.)?([A-Za-z_]\w*)\s*(?::[^=]+)?=", stripped)
    if assignment and "==" not in stripped:
        name = assignment.group(1)
        return f"计算并保存 `{name}`（{humanize_name(name)}），供后续逻辑使用{where}。"
    if suffix == ".ps1" and stripped.startswith("$"):
        return f"执行 PowerShell 配置或变量操作：`{stripped[:80]}`。"
    if suffix == ".bat" and stripped.lower().startswith(("set ", "cd ", "python ", "powershell ", "start ")):
        return f"执行 Windows 启动脚本命令：`{stripped[:80]}`。"
    return f"执行当前业务语句，完成数据构造、函数调用或状态更新{where}。"


def escape_markdown_cell(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("|", "&#124;")
        .replace("`", "&#96;")
        .replace("\t", "    ")
    )


def write_annotated_file(path: Path, symbols: list[Symbol], contexts: dict[int, str], string_lines: set[int]) -> list[str]:
    relative = path.relative_to(ROOT)
    purpose = SCRIPT_PURPOSES.get(path.name, f"辅助脚本：根据文件名 `{path.name}` 完成对应的数据处理或运维任务。")
    lines = path.read_text(encoding="utf-8-sig", errors="replace").splitlines()
    output_name = f"{relative.as_posix().replace('/', '__')}.逐行注释.md"
    output_path = OUTPUT_DIR / "逐文件" / output_name
    output_path.parent.mkdir(parents=True, exist_ok=True)
    rendered = [
        f"# `{relative.as_posix()}` 逐行注释",
        "",
        f"**脚本用途：** {purpose}",
        "",
        f"**源码行数：** {len(lines)}　**函数/类数量：** {len(symbols)}",
        "",
        "| 行号 | 中文说明 | 原始源码 |",
        "|---:|---|---|",
    ]
    plain: list[str] = [f"===== 文件：{relative.as_posix()} =====", f"脚本用途：{purpose}"]
    for index, source in enumerate(lines, 1):
        explanation = describe_line(source, index, path.suffix.lower(), contexts.get(index, ""), string_lines)
        source_display = source if source else "<空行>"
        rendered.append(f"| L{index:04d} | {escape_markdown_cell(explanation)} | <code>{escape_markdown_cell(source_display)}</code> |")
        plain.append(f"[L{index:04d}][说明] {explanation}")
        plain.append(f"[L{index:04d}][源码] {source_display}")
    output_path.write_text("\n".join(rendered) + "\n", encoding="utf-8")
    plain.append("")
    return plain


def find_topic_matches(files: list[Path], patterns: list[str]) -> list[tuple[str, int, str]]:
    matches: list[tuple[str, int, str]] = []
    preferred_names = [pattern.lower() for pattern in patterns if Path(pattern).suffix.lower() in SUPPORTED_SUFFIXES]
    lowered = [pattern.lower() for pattern in patterns if pattern.lower() not in preferred_names]
    ordered_files = sorted(
        files,
        key=lambda path: (
            preferred_names.index(path.name.lower()) if path.name.lower() in preferred_names else len(preferred_names),
            path.as_posix(),
        ),
    )
    for path in ordered_files:
        relative = path.relative_to(ROOT).as_posix()
        lines = path.read_text(encoding="utf-8-sig", errors="replace").splitlines()
        for line_no, line in enumerate(lines, 1):
            haystack = line.lower()
            if any(pattern in haystack for pattern in lowered):
                matches.append((relative, line_no, line.strip()))
                if len(matches) >= 12:
                    return matches
    return matches


def write_readme(files: list[Path], all_symbols: list[Symbol], line_count: int) -> None:
    rows = [
        "# 比赛答辩 scripts 代码速查",
        "",
        "> 本目录是运行源码的只读讲解副本。不要从这里启动服务；实际运行文件仍在 `scripts/`。",
        "",
        "## 使用方法",
        "",
        "1. 不确定某项技术在哪时，先在本文件搜索“抓包”“融合评分”“RAG”“封禁”“态势报告”等关键词。",
        "2. 已知函数或接口名时，打开 `函数与接口索引.md` 搜索名称，可直接看到源码文件和原始行号。",
        "3. 想逐行解释时，打开 `逐文件/` 下对应文件，或在 `全部脚本逐行注释.txt` 中全局搜索。",
        "4. 行号对应生成时的本地源码；代码更新后运行 `python devtools/generate_competition_code_guide.py` 刷新。",
        "",
        "## 覆盖统计",
        "",
        f"- 脚本文件：{len(files)} 个",
        f"- 原始源码：{line_count} 行",
        f"- 函数、类：{len(all_symbols)} 个",
        "- 每一行均保留原始行号、源码和中文说明。",
        "",
        "## 高频答辩问题入口",
        "",
    ]
    for topic, patterns in ANSWER_TOPICS.items():
        rows.extend([f"### {topic}", ""])
        matches = find_topic_matches(files, patterns)
        if not matches:
            rows.append("- 暂无匹配。")
        else:
            for file, line, source in matches[:8]:
                preview = source.replace("`", "'")[:110]
                rows.append(f"- `{file}:{line}`　`{preview}`")
        rows.append("")
    rows.extend(["## 脚本用途总览", "", "| 脚本 | 主要职责 |", "|---|---|"])
    for path in files:
        relative = path.relative_to(ROOT).as_posix()
        purpose = SCRIPT_PURPOSES.get(path.name, "辅助数据处理、测试、训练或运维脚本。")
        rows.append(f"| `{relative}` | {purpose} |")
    (OUTPUT_DIR / "README.md").write_text("\n".join(rows) + "\n", encoding="utf-8")


def write_symbol_index(symbols: list[Symbol], routes: list[tuple[str, int, str]]) -> None:
    rows = [
        "# 函数、类与 Flask 接口索引",
        "",
        "## Flask 接口",
        "",
        "| 文件与行号 | 路由定义 |",
        "|---|---|",
    ]
    for file, line, route in routes:
        rows.append(f"| `{file}:{line}` | `{route.replace('`', "'")}` |")
    rows.extend(["", "## 函数与类", "", "| 名称 | 类型 | 文件与范围 | 定义 |", "|---|---|---|---|"])
    for symbol in sorted(symbols, key=lambda item: (item.name.lower(), item.file, item.line)):
        parent = f"（属于 `{symbol.parent}`）" if symbol.parent else ""
        signature = symbol.signature.replace("|", "&#124;").replace("`", "'")
        rows.append(
            f"| `{symbol.name}` {parent} | {symbol.kind} | `{symbol.file}:{symbol.line}-{symbol.end_line}` | `{signature}` |"
        )
    (OUTPUT_DIR / "函数与接口索引.md").write_text("\n".join(rows) + "\n", encoding="utf-8")


def main() -> None:
    files = iter_source_files()
    if OUTPUT_DIR.exists():
        shutil.rmtree(OUTPUT_DIR)
    (OUTPUT_DIR / "逐文件").mkdir(parents=True, exist_ok=True)

    all_symbols: list[Symbol] = []
    all_plain: list[str] = []
    routes: list[tuple[str, int, str]] = []
    total_lines = 0
    for path in files:
        text = path.read_text(encoding="utf-8-sig", errors="replace")
        lines = text.splitlines()
        total_lines += len(lines)
        if path.suffix.lower() == ".py":
            symbols, contexts, string_lines = collect_python_metadata(path, text)
        else:
            symbols, contexts, string_lines = [], {}, set()
        all_symbols.extend(symbols)
        relative = path.relative_to(ROOT).as_posix()
        for line_no, line in enumerate(lines, 1):
            if "@app.route" in line or "@bp.route" in line:
                routes.append((relative, line_no, line.strip()))
        all_plain.extend(write_annotated_file(path, symbols, contexts, string_lines))

    write_readme(files, all_symbols, total_lines)
    write_symbol_index(all_symbols, routes)
    # UTF-8 BOM lets Windows Notepad and common IDEs recognize Chinese reliably.
    (OUTPUT_DIR / "全部脚本逐行注释.txt").write_text("\n".join(all_plain), encoding="utf-8-sig")
    print(
        f"generated files={len(files)} lines={total_lines} symbols={len(all_symbols)} "
        f"routes={len(routes)} output={OUTPUT_DIR}"
    )


if __name__ == "__main__":
    main()
