# 比赛答辩 scripts 代码速查

> 本目录是运行源码的只读讲解副本。不要从这里启动服务；实际运行文件仍在 `scripts/`。

## 使用方法

1. 不确定某项技术在哪时，先在本文件搜索“抓包”“融合评分”“RAG”“封禁”“态势报告”等关键词。
2. 已知函数或接口名时，打开 `函数与接口索引.md` 搜索名称，可直接看到源码文件和原始行号。
3. 想逐行解释时，打开 `逐文件/` 下对应文件，或在 `全部脚本逐行注释.txt` 中全局搜索。
4. 行号对应生成时的本地源码；代码更新后运行 `python devtools/generate_competition_code_guide.py` 刷新。

## 覆盖统计

- 脚本文件：45 个
- 原始源码：24379 行
- 函数、类：869 个
- 每一行均保留原始行号、源码和中文说明。

## 高频答辩问题入口

### 抓包与网卡选择

- `scripts/capture_http_request_batches.py:27`　`MAX_TSHARK_FIELD_CHARS = MAX_CAPTURE_PAYLOAD_CHARS * 4`
- `scripts/capture_http_request_batches.py:62`　`f"未找到可执行文件: {name}，请确认 Wireshark/TShark 已安装并加入 PATH，"`
- `scripts/capture_http_request_batches.py:106`　`def list_interfaces(tshark_exe: str, timeout: Optional[int] = None):`
- `scripts/capture_http_request_batches.py:107`　`output = run_text_command([tshark_exe, "-D"], timeout=timeout)`
- `scripts/capture_http_request_batches.py:108`　`interfaces = []`
- `scripts/capture_http_request_batches.py:118`　`interfaces.append({"index": idx, "raw": rest})`
- `scripts/capture_http_request_batches.py:119`　`return interfaces`
- `scripts/capture_http_request_batches.py:122`　`def choose_interface(interfaces, preferred_name: str = "") -> str:`

### 三个小模型与融合评分

- `scripts/security_detection_v2.py:17`　`DEFAULT_MODEL_PATH = PROJECT_ROOT / "models" / "payload_model_v2.joblib"`
- `scripts/security_detection_v2.py:18`　`DEFAULT_BEHAVIOR_MODEL_PATH = PROJECT_ROOT / "models" / "behavior_model_v2.joblib"`
- `scripts/security_detection_v2.py:179`　`def payload_model_text(event: Dict[str, Any]) -> str:`
- `scripts/security_detection_v2.py:296`　`class PayloadModel:`
- `scripts/security_detection_v2.py:310`　`text = payload_model_text(event)`
- `scripts/security_detection_v2.py:324`　`class BehaviorWindowAnalyzer:`
- `scripts/security_detection_v2.py:325`　`def __init__(self, window_minutes: int = 5, model_path: Path | str = DEFAULT_BEHAVIOR_MODEL_PATH):`
- `scripts/security_detection_v2.py:342`　`def observe(self, event: Dict[str, Any], payload_or_rule_hit: bool = False) -> Dict[str, Any]:`

### POC 规则引擎

- `scripts/web_attack_rules.py:54`　`ATTACK_RULES = [`
- `scripts/web_attack_rules.py:57`　`"rule_score": 0.94,`
- `scripts/web_attack_rules.py:71`　`"rule_score": 0.93,`
- `scripts/web_attack_rules.py:85`　`"rule_score": 0.94,`
- `scripts/web_attack_rules.py:94`　`"rule_score": 0.90,`
- `scripts/web_attack_rules.py:103`　`"rule_score": 0.88,`
- `scripts/web_attack_rules.py:112`　`"rule_score": 0.89,`
- `scripts/web_attack_rules.py:123`　`for rule in ATTACK_RULES:`

### 大模型最终研判

- `scripts/llm_analyzer_daemon.py:22`　`def _cached_review_ready_at(event_time, now=None) -> Optional[datetime]:`
- `scripts/llm_analyzer_daemon.py:148`　`# semantic review payload compact so CPU-only Ollama can answer fast.`
- `scripts/llm_analyzer_daemon.py:375`　`def load_review_api_config(path: Path) -> Dict:`
- `scripts/llm_analyzer_daemon.py:376`　`"""Load the private OpenAI-compatible final-review configuration."""`
- `scripts/llm_analyzer_daemon.py:390`　`api_key = str(config.get("api_key") or os.environ.get("LLM_REVIEW_API_KEY") or "").strip()`
- `scripts/llm_analyzer_daemon.py:392`　`raise RuntimeError("external_review_api_key_missing")`
- `scripts/llm_analyzer_daemon.py:398`　`# DeepSeek V4 defaults to thinking mode. Event review needs the final`
- `scripts/llm_analyzer_daemon.py:437`　`raise RuntimeError("external_review_empty_choices")`

### RAG 文档切片与向量召回

- `scripts/rag_service.py:3`　`MySQL stores auditable metadata and chunk text. LanceDB stores vectors. Cloud`
- `scripts/rag_service.py:4`　`calls are limited to embedding and reranking so the existing Ollama report`
- `scripts/rag_service.py:28`　`DEFAULT_EMBEDDING_MODEL = "text-embedding-v4"`
- `scripts/rag_service.py:75`　`"embedding_model": str(payload.get("embedding_model") or DEFAULT_EMBEDDING_MODEL),`
- `scripts/rag_service.py:77`　`"embedding_dimensions": int(payload.get("embedding_dimensions") or 1024),`
- `scripts/rag_service.py:107`　`f"{config['base_url']}/embeddings",`
- `scripts/rag_service.py:109`　`{"model": config["embedding_model"], "input": batch, "dimensions": config["embedding_dimensions"]},`
- `scripts/rag_service.py:115`　`result.extend([[float(v) for v in row["embedding"]] for row in rows])`

### DeepSeek/外部 API 并发

- `scripts/llm_analyzer_daemon.py:1296`　`executor = concurrent.futures.ThreadPoolExecutor(`
- `scripts/rag_service.py:64`　`or "https://dashscope.aliyuncs.com/compatible-mode/v1"`
- `scripts/rag_service.py:69`　`or base_url.replace("/compatible-mode/v1", "/compatible-api/v1/reranks")`

### 自动防御与真实封禁

- `scripts/fast_defense.py:21`　`from firewall_control import firewall_block_ip, firewall_status, is_safe_automatic_target, normalize_ip_litera`
- `scripts/fast_defense.py:23`　`from scripts.firewall_control import firewall_block_ip, firewall_status, is_safe_automatic_target, normalize_i`
- `scripts/fast_defense.py:110`　`if bool(row.get("instant_block", True))`
- `scripts/fast_defense.py:250`　`def _already_blocked(self, cur: Any, ip_address: str) -> bool:`
- `scripts/fast_defense.py:251`　`cur.execute("SELECT id FROM demo_blocked_ips WHERE ip_address=%s LIMIT 1", (ip_address,))`
- `scripts/fast_defense.py:263`　`cur.execute("SHOW COLUMNS FROM demo_blocked_ips LIKE 'defense_latency_ms'")`
- `scripts/fast_defense.py:266`　`"ALTER TABLE demo_blocked_ips "`
- `scripts/fast_defense.py:267`　`"ADD COLUMN defense_latency_ms DOUBLE NULL AFTER blocked_role"`

### 态势关联与多代理聚合

- `scripts/situation_cluster.py:20`　`def _build_report(cluster: Dict[str, Any]) -> Dict[str, Any]:`
- `scripts/situation_cluster.py:21`　`ips = cluster["source_ips"]`
- `scripts/situation_cluster.py:22`　`labels = cluster["action_labels"]`
- `scripts/situation_cluster.py:23`　`duration = max(1, int(cluster["duration_seconds"] / 60))`
- `scripts/situation_cluster.py:26`　`proxy_note = "来源地址高频切换，具有代理池或分布式协同行为特征" if cluster["proxy_rotation_suspected"] else "多个来源在相近时间针对同一资产执行相似动作"`
- `scripts/situation_cluster.py:29`　`f"系统在 {duration} 分钟内关联到 {len(ips)} 个来源 IP，针对 {cluster['target_asset']} "`
- `scripts/situation_cluster.py:30`　`f"累计实施 {cluster['total_action_count']} 次、{cluster['distinct_action_types']} 类安全动作。{proxy_note}。"`
- `scripts/situation_cluster.py:34`　`"timeline_analysis": f"聚合窗口从 {cluster['started_at']} 至 {cluster['last_action_at']}，持续约 {duration} 分钟；同一目标和紧密时间`

### 普通与专业态势报告

- `scripts/situation_ai.py:15`　`REPORT_FIELDS = {`
- `scripts/situation_ai.py:46`　`def fallback_report(situation: Dict[str, Any], reason: str = "") -> Dict[str, Any]:`
- `scripts/situation_ai.py:58`　`report = {`
- `scripts/situation_ai.py:132`　`report["fallback_reason"] = reason[:500]`
- `scripts/situation_ai.py:133`　`return report`
- `scripts/situation_ai.py:152`　`def validate_report(report: Dict[str, Any], *, allow_success_claims: bool = False) -> Dict[str, Any]:`
- `scripts/situation_ai.py:153`　`missing = [field for field in REPORT_FIELDS if not report.get(field)]`
- `scripts/situation_ai.py:156`　`# Older reports remain readable while newly generated reports provide a`

### MySQL 数据留痕

- `scripts/build_result_db.py:529`　`CREATE TABLE IF NOT EXISTS requests (`
- `scripts/build_result_db.py:548`　`CREATE TABLE IF NOT EXISTS responses (`
- `scripts/build_result_db.py:559`　`CREATE TABLE IF NOT EXISTS analyses (`
- `scripts/build_result_db.py:620`　`CREATE TABLE IF NOT EXISTS requests (`
- `scripts/build_result_db.py:641`　`CREATE TABLE IF NOT EXISTS responses (`
- `scripts/build_result_db.py:654`　`CREATE TABLE IF NOT EXISTS analyses (`
- `scripts/build_result_db.py:688`　`CREATE TABLE IF NOT EXISTS demo_attack_events (`
- `scripts/build_result_db.py:718`　`CREATE TABLE IF NOT EXISTS ip_geo_cache (`

### 4000 靶场与指纹快速路径

- `scripts/target_multivuln_lab.py:391`　`{"name": "Web 服务端口", "method": "POST", "url": "/api/recon/ports", "contentType": "application/json", "body": {`
- `scripts/build_result_db.py:1189`　`"protection_action": str(analysis_obj.get("summary") or "\u81ea\u52a8\u8bc6\u522b\u5230\u53ef\u7591\u6d41\u91c`
- `scripts/dashboard_api_server.py:1836`　`request_fingerprint CHAR(64) NOT NULL,`
- `scripts/fast_defense.py:29`　`request_fingerprint CHAR(64) NOT NULL,`
- `scripts/fast_defense.py:69`　`fingerprint: str`
- `scripts/fast_defense.py:136`　`fingerprint_text = "|".join(`
- `scripts/fast_defense.py:161`　`fingerprint=hashlib.sha256(fingerprint_text.encode("utf-8", errors="replace")).hexdigest(),`
- `scripts/fast_defense.py:287`　`request_fingerprint,source_ip,destination_ip,method,uri,category,score,`

### Flask 接口与 JWT 权限

- `scripts/dashboard_api_server.py:2381`　`def require_roles(*roles: str):`
- `scripts/dashboard_api_server.py:2524`　`@app.route("/api/v1/screen/ping", methods=["GET"])`
- `scripts/dashboard_api_server.py:2528`　`@app.route("/api/v2/auth/demo-accounts", methods=["GET"])`
- `scripts/dashboard_api_server.py:2534`　`@app.route("/api/v2/auth/register", methods=["POST"])`
- `scripts/dashboard_api_server.py:2596`　`@app.route("/api/v2/auth/login", methods=["POST"])`
- `scripts/dashboard_api_server.py:2624`　`@app.route("/api/v2/auth/logout", methods=["POST"])`
- `scripts/dashboard_api_server.py:2625`　`@require_roles(ROLE_NORMAL, ROLE_ADMIN)`
- `scripts/dashboard_api_server.py:2632`　`@app.route("/api/v2/auth/profile", methods=["GET"])`

## 脚本用途总览

| 脚本 | 主要职责 |
|---|---|
| `scripts/auto_defense_daemon.py` | 根据已确认攻击事件执行自动封禁，并处理配置开关与重复操作。 |
| `scripts/build_demo_candidates.py` | 辅助数据处理、测试、训练或运维脚本。 |
| `scripts/build_rag_db.py` | 从种子知识文件构建兼容的本地 RAG 索引。 |
| `scripts/build_result_db.py` | 创建结果数据库表结构并导入历史 result 文件。 |
| `scripts/capture_http_request_batches.py` | 调用 TShark 实时抓取 HTTP 流量，解析请求/响应并触发快速防御与检测流水线。 |
| `scripts/dashboard_api_server.py` | Flask 后端主服务：JWT 鉴权、用户与管理员接口、态势大屏、RAG 管理、自动防御、报告任务和数据库查询。 |
| `scripts/demo_workflow.py` | 执行旧模型兼容筛选、候选导出和检测结果组织。 |
| `scripts/evaluate_detection_v2.py` | 评估新检测架构的准确率、精确率、召回率和 F1。 |
| `scripts/export_demo_candidates_to_result.py` | 辅助数据处理、测试、训练或运维脚本。 |
| `scripts/extract_old_model_features_from_txt.py` | 辅助数据处理、测试、训练或运维脚本。 |
| `scripts/fast_defense.py` | 自动防御快速路径：匹配高确定性规则并调用防火墙控制，缩短封禁时间。 |
| `scripts/firewall_control.py` | Windows 防火墙双向封禁与解封实现，维护安全操作记录。 |
| `scripts/iterative_threshold_tuning.py` | 迭代实验不同阈值，比较正常/攻击流量并输出调参结论。 |
| `scripts/llm_analyzer_daemon.py` | 大模型研判守护进程：消费候选事件、检索 RAG、调用本地或外部模型并写回结构化结论。 |
| `scripts/pipeline_events.py` | 提供轻量事件通知，减少文件轮询造成的流水线等待。 |
| `scripts/port_scan_sensor.py` | 从 TCP SYN/连接行为中识别端口扫描并写入行为证据。 |
| `scripts/rag_service.py` | RAG 知识库核心：文档解析、切片、向量化、召回、重排、阈值判断和回归评估。 |
| `scripts/raw_llm_review.py` | RAW 候选事件并发复核、DeepSeek/OpenAI 兼容 API 调用、缓存与任务状态管理。 |
| `scripts/real_capture_threshold_compare.py` | 使用真实抓包数据比较阈值效果。 |
| `scripts/rerank_model_result.py` | 辅助数据处理、测试、训练或运维脚本。 |
| `scripts/result_db_daemon.py` | 持续扫描 result 目录并把请求、响应、分析结论同步到 MySQL。 |
| `scripts/run_capture_compare_admin_once.ps1` | 辅助数据处理、测试、训练或运维脚本。 |
| `scripts/run_demo_daemon.py` | 监控 input 目录并调度小模型检测工作流。 |
| `scripts/run_old_model_direct.py` | 辅助数据处理、测试、训练或运维脚本。 |
| `scripts/security_detection_v2.py` | 新架构融合检测核心：Payload 模型、POC 规则、行为窗口和上下文证据融合。 |
| `scripts/seed_authoritative_rag.py` | 导入 OWASP 等权威安全知识，建立可用于研判的初始知识库。 |
| `scripts/seed_lab_review_cache.py` | 辅助数据处理、测试、训练或运维脚本。 |
| `scripts/seed_situation_demo.py` | 辅助数据处理、测试、训练或运维脚本。 |
| `scripts/situation_ai.py` | 调用外部 API 生成普通 AI 态势报告并校验结构化结果。 |
| `scripts/situation_ai_daemon.py` | 消费普通态势报告队列，处理优先级、重试、超时和状态回写。 |
| `scripts/situation_cluster.py` | 跨 IP 聚类与多代理协同态势识别。 |
| `scripts/situation_core.py` | 按来源、时间和攻击阶段关联事件，形成单 IP 攻击态势。 |
| `scripts/situation_daemon.py` | 周期性读取攻击事件并生成、更新攻击者态势。 |
| `scripts/situation_neo4j_sync.py` | 可选 Neo4j 图数据同步，实现攻击者、动作和资产关系映射。 |
| `scripts/situation_professional_report.py` | 生成专业态势报告及 PDF/Word 文档，负责模板、表格、图形和版式。 |
| `scripts/situation_store.py` | 态势、动作、证据、报告和队列数据的 MySQL 持久化访问层。 |
| `scripts/situation_supervisor.py` | 态势子服务监护器，启动并检查端口扫描、态势聚合和 AI 报告进程。 |
| `scripts/ssh_bruteforce_monitor.py` | 读取 Windows SSH 登录失败日志，按时间窗聚合 SSH 暴力破解。 |
| `scripts/sync_detection_v2_db.py` | 将新架构候选、模型预测、POC 命中和行为窗口同步到数据库。 |
| `scripts/sync_raw_http_logs.py` | 将原始 HTTP 流量同步到 MySQL，供新检测链路和审计回溯使用。 |
| `scripts/target_multivuln_lab.py` | 4000 端口多漏洞靶场，提供信息收集、经典漏洞、Nday 和模拟 0day 测试入口。 |
| `scripts/train_behavior_model_v2.py` | 训练扫描、爆破等行为窗口模型。 |
| `scripts/train_payload_model_v2.py` | 训练 Payload 文本/特征模型并保存模型与评估结果。 |
| `scripts/train_synthetic_web_mlp.py` | 生成与训练兼容旧链路的 Web 流量 MLP 模型。 |
| `scripts/web_attack_rules.py` | Web 攻击 POC 规则库，识别 SQL 注入、XSS、命令注入、路径遍历、SSRF、XXE 等典型载荷。 |
