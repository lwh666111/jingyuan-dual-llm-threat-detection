# 靖渊智御：AI 驱动的外部 Web 威胁态势感知平台

面向实战流量的端到端安全分析系统，覆盖抓包、检测、LLM 研判、RAG 增强、结果入库、API 服务与前端大屏。

当前版本核心链路：

- 监听指定网卡和端口，抓取完整 HTTP 请求/响应
- 生成标准化批次文件（`input/1.1.n.txt`）
- Detection V2 通过 Payload 模型、POC 规则和行为窗口形成融合候选，再由 LLM 完成最终攻击判定
- Ollama 本地研判 + 百炼向量模型 + LanceDB/BM25/RRF/qwen3-rerank 混合 RAG
- MySQL 持久化（兼容旧三表，并新增 raw/candidate/event/model/rule/behavior 分层表）
- Flask API（3049）+ Node 前端大屏（1145）
- 跨传感器攻击态势关联：端口扫描、SSH 爆破、HTTP 漏洞利用按来源 IP 与时间窗串联
- AI 态势报告：普通态势报告与专业 PDF 报告统一调用阿里云百炼 API，对完整攻击链给出时间线、技术路径、证据强度、影响、失陷判断、结论、调查步骤和分阶段处置建议，不占用服务器本机 Ollama 推理资源
- 静默快速防御：开启自动防御后，高置信典型攻击在抓包入口以确定性规则异步写入 Windows 双向防火墙；请求仍完整进入原有检测与 AI 链路

## 最新发布（2026-08-11）

- RAW 数据库原生链路成为实时主链路：三层检测只负责筛选，未经 LLM 确认的候选不得进入正式大屏和态势关联。
- 新增 MySQL 持久化 `llm_review_jobs` 队列，进程重启不丢任务；新候选每秒轮询并优先于历史 `result/b.*` 兼容任务。
- 详情页新增 LLM 最终结论、模型、置信度、证据、RAG 命中数和研判耗时，右侧详情使用卡片内独立滚动。
- 事件最终研判支持外部 OpenAI 兼容 API 并发处理；指纹完全匹配的 4000 靶场样本维持 5–8 秒确定性直出，其他候选事件继续经过 RAG 与最终研判。
- 服务器实测：指纹样本约 6 秒发布，非指纹 XSS 经 RAG 与外部最终研判约 11 秒发布；正常登录仅保留原始日志。

- 版本记录：`docs/VERSION_RECORD.md`
- 更新日志：`docs/CHANGELOG_2026-04_2026-05.md`
- 最新使用教程：`docs/USAGE.md`
- Detection V2 实验与落地记录：`docs/DETECTION_V2_PROGRESS_2026-07-01.md`
- 连续攻击态势设计与使用说明：`docs/SITUATION_INTELLIGENCE.md`
- 最新安装包：`dist/JingyuanTrafficPipeline_Setup_ManualDeps.exe`
- 安装包校验：安装后可在发布机器执行 `Get-FileHash .\dist\JingyuanTrafficPipeline_Setup_ManualDeps.exe -Algorithm SHA256` 查看

## GitHub 仓库简介
`靖渊智御：AI 驱动的外部 Web 威胁态势感知平台，支持真实抓包、多模型筛选、云端大模型+RAG 最终研判、MySQL 入库、态势关联、大屏展示、自动防御、靶场测试与一键启动。`

## 主要能力

- 统一入口：`app.py`
- 一键部署：`deploy/start_all.ps1`（MySQL + Ollama + RAG + 全链路服务）
- 可配置多端口监听（如 `80,3000,10086`）
- 基于完整 HTTP 请求/响应配对的批次采集（非原始切片）
- 自动检测守护 + LLM 研判守护 + 自动入库守护
- 前端角色权限：普通用户 / 管理员
- 企业级 RAG 工作台：多知识库、附件解析、语义切片、向量索引、切片编辑、召回测试、批量回归评估与历史留痕
- 扩展插件：钓鱼网站检测工具（后端代理调用）
- 攻击详情支持一键封禁来源 IP
- 管理员系统配置支持模型/网卡/端口/分组数量/主页背景图配置
- 高危异常流量触发机械音提醒：“注意异常流量”
- 内置新训练的 Web 攻击检测模型，降低普通登录误报，增强 SQL/XSS/命令注入/路径遍历/危险上传识别
- 行为型攻击聚合上报：目录扫描、路径探测、高频请求、HTTP 爆破不会按每条请求刷屏，而是按来源 IP、攻击类型和时间窗口汇总成少量告警
- SSH 爆破监控：自动读取 Windows `Security 4625` 与 `OpenSSH/Operational` 失败登录日志，达到阈值后写入大屏攻击事件
- 连续态势关联：同一来源、同一目标在短时间内出现至少 3 类不同动作后形成攻击者态势；重复单类请求只累计次数，不增加动作多样性
- 端口扫描传感器：基于 TCP SYN 唯一目标端口数量聚合，避免把同端口高频请求误判为端口扫描
- 态势可视化：攻击者列表、阶段链路、动作间隔、风险指数、证据序列与 AI/RAG 报告同屏展示
- 态势链路聚合：默认合并连续同类动作并将超长链压缩到约 10 个阶段节点，仍可切换“证据视图”查看全部原始动作
- 全链路验证靶场：按信息收集、经典漏洞、公开 N-day 特征和未知威胁结构四阶段组织，并提供一键顺序回放
- 管理员可调参数：动作种类阈值、关联窗口、静默切段、扫描端口阈值和扫描窗口保存后由守护进程动态应用
- 可选 Neo4j 图镜像：MySQL 保持权威主存储，Neo4j 仅用于图查询与后续溯源扩展；Neo4j 故障不阻断主流程
- 后端快速防御层：覆盖高置信 SQL 注入、XSS、命令注入、目录穿越、XXE、SSRF、SSTI、反序列化、典型 N-day 与 WebShell 上传特征。规则命中仅执行封禁和内部审计，不生成前端告警；未命中及已命中的请求都继续进入 Payload/POC/行为窗口/态势/LLM-RAG 链路

### 自动防御执行顺序

```text
HTTP 请求进入抓包入口
  -> 自动防御未开启：直接进入原有全链路
  -> 自动防御已开启：约 0.15 ms 高置信规则判断
       -> 命中：后台队列立即创建入站 + 出站 Windows 防火墙规则，并写内部审计
       -> 未命中：不执行快速封禁
  -> 无论是否命中，继续保存 input 并运行 Detection V2、POC、行为窗口、态势关联和 LLM/RAG
```

快速规则位于 `rules/fast_defense_rules.json`，仅选择低误报、证据充分的组合特征；正常目录访问、普通登录和单一模糊关键词不会触发该层。`demo_fast_defense_audit` 仅用于后台排障，没有前端查询接口。封禁结果仍进入统一封禁列表，因此管理员可以使用原有解封能力。

## 高级 RAG 知识库（2026-08）

“大模型设置”中的知识库管理已升级为完整工作台。管理员可以创建多个相互隔离的知识库，上传 `PDF/DOCX/PPTX/XLSX/Markdown/JSON/CSV/TXT` 文档，查看解析状态与切片，在线修改切片并自动重建向量，还可以执行真实召回测试、维护回归用例并批量查看通过率与失败原因。

检索链路：

```text
安全事件证据
 -> text-embedding-v4 云端向量化
 -> LanceDB 向量召回 + 本地 BM25 关键词召回
 -> RRF 融合候选
 -> qwen3-rerank 云端重排
 -> Top-K 证据片段与来源引用
 -> 外部兼容 API 完成事件最终研判，百炼 API 生成态势报告
```

百炼承担嵌入、重排与态势报告生成；候选事件通过独立外部 API 并发完成最终研判。云端向量服务暂时不可用时，RAG 会退回本地 BM25/旧知识检索，不影响原始流量留存和小模型筛选。

1. 将 `config/ai_api.example.json` 复制为 `config/ai_api.local.json`。
2. 填写自己的百炼 `api_key`、工作空间 `base_url` 和 `rerank_url`。
3. 不要把 `config/ai_api.local.json` 提交到 Git；该文件已加入 `.gitignore`。
4. 默认向量和上传文件位于 `D:\JingyuanTrafficPipelineData\rag`，可通过 `--rag-data-dir` 或环境变量 `RAG_DATA_DIR` 修改。
5. 执行 `python app.py` 后，MySQL 会增量创建 RAG 表并迁移旧 SQLite 知识，不删除旧库。

事件最终研判 API 使用独立私密配置：

1. 将 `config/llm_review_api.example.json` 复制为 `config/llm_review_api.local.json`。
2. 填写自己的 `api_key`、`base_url` 和模型名称；默认并发工作线程为 8。
3. 私密文件已加入 `.gitignore`，禁止提交真实密钥。
4. 完全命中 4000 靶场指纹的事件不会调用外部 API；其余候选事件才进入 RAG 与外部最终研判。

导入官方安全知识：

```powershell
python scripts/seed_authoritative_rag.py --data-dir D:\JingyuanTrafficPipelineData\rag
```

脚本使用三类权威来源，并在首次初始化时建立 SQL 注入、XSS、端口扫描三条基础回归用例：

- OWASP Cheat Sheet Series：`https://github.com/OWASP/CheatSheetSeries`
- MITRE ATT&CK Enterprise STIX 2.1：`https://github.com/mitre-attack/attack-stix-data`
- CISA Known Exploited Vulnerabilities：`https://www.cisa.gov/known-exploited-vulnerabilities-catalog`

测试上传文件位于 `test\rag_upload_samples\Web攻击研判知识测试样例.md`。

## 连续攻击态势

普通攻击事件回答“这一条请求像什么”，连续态势回答“同一个攻击者在一段时间内做了什么、动作如何推进、下一步风险是什么”。默认关联规则如下：

```text
同一来源 IP + 同一目标资产
  -> 30 分钟关联窗口
  -> 15 分钟无新动作则切分会话
  -> 至少 3 类不同动作
  -> observing / open / closed / handled / ignored
```

例如，端口扫描、SSH 爆破和 SQL 注入会按时间顺序形成一条链；同一来源连续发送 1 万条目录扫描请求仍只算一种动作，并聚合为一个证据节点。LLM 不负责决定是否形成态势，只对已经由确定性规则形成的证据链进行解释，因此不会因大模型波动改变基础告警结果。

启动后，普通用户和管理员均可从顶部导航进入“态势感知展示”。管理员还可在“系统配置”调整关联阈值，并对态势执行重新研判、标记已处置或忽略。

态势 AI 报告面向处置人员提供执行摘要、事件叙述、时间线分析、技术分析、证据强度、影响评估、失陷判断、综合结论、调查步骤、即时防护、检测优化、长期改进和证据边界。报告不能取代原始证据，也不得在缺少成功响应、主机执行或持久化证据时把“攻击尝试”写成“入侵成功”。

可选 Neo4j 镜像启动示例：

```powershell
python app.py --neo4j-url http://127.0.0.1:7474 --neo4j-user neo4j --neo4j-password YOUR_PASSWORD
```

不传 `--neo4j-url` 和 `--neo4j-password` 时不会启动图镜像，不影响任何现有功能。完整架构、数据表和接口说明见 `docs/SITUATION_INTELLIGENCE.md`。

## Detection V2 检测架构

新版本不再把“访问过某个路径”直接等价为攻击事件，而是采用分层判定：

```text
原始 HTTP 请求/响应
 -> Payload 模型
 -> POC 规则引擎
 -> 行为窗口分析
 -> 融合评分
 -> raw_only（直接留痕）/ candidate（进入 LLM 队列）
 -> Ollama 最终研判
 -> attack：attack_event + MySQL + 大屏 + 态势关联
 -> benign/unknown：不进入正式攻击展示
```

- `raw_only`：仅作为原始日志保留，不进入大屏告警。
- `candidate`：三层融合筛出的待研判流量，写入持久化 LLM 队列，但此时不进入正式大屏。
- `attack_event`：仅指 LLM 最终确认的攻击事件，进入 MySQL 正式事件表、大屏和态势关联。

当前已内置：

- `models/payload_model_v2.joblib`
- `rules/poc_rules.json`
- `scripts/security_detection_v2.py`
- `scripts/train_behavior_model_v2.py`
- `scripts/sync_raw_http_logs.py`
- `scripts/sync_detection_v2_db.py`

详情页已接入完整证据链，可查看融合评分、Payload 模型置信度、POC 命中、行为窗口、LLM/RAG 最终研判和原始请求/响应。历史 `result/b.*` 数据仍可读取，但常驻守护默认不再处理其重试积压；需要兼容处理时可单独执行 `llm_analyzer_daemon.py --legacy-result-review`。

2026-07-01 重构补齐项：

- `input/1.1.n.txt` 会先全量入库到 `raw_http_logs`，正常访问只保留原始日志，不进入告警。
- V2 检测出的 `attack_event` 会同步写入 `demo_attack_events`，大屏和详情信息能实时刷新。
- V2 检测出的 `candidate` 会进入管理员/专业详情页的“候选事件复核队列”，可查看、提升为攻击事件或忽略。
- 新增 `models/behavior_model_v2.joblib` 行为窗口模型，用于识别暴力破解、扫描、目录探测、高频请求等仅靠单包 Payload 难以判断的行为。
- Payload 模型补充正常登录 hard negative，融合层收紧“认证接口 + 模型高分”规则，降低普通账号密码登录误报。
- 行为型攻击新增聚合事件 ID：同一来源 IP 在同一时间桶内的大量目录扫描、路径探测、高频请求或 HTTP 爆破只更新同一条告警，避免几万字典扫描产生几万条疑似流量。
- 新增 SSH 爆破独立监控进程 `scripts/ssh_bruteforce_monitor.py`，随 `app.py` 默认启动；可通过 `--no-ssh-monitor` 关闭。

## Project Layout

```text
.
├─ app.py
├─ scripts/
├─ config/
├─ Dockerfile
├─ docker-compose.yml
├─ docs/
├─ input/
├─ output/
├─ result/
├─ requirements.txt
├─ CONTRIBUTING.md
├─ SECURITY.md
├─ LICENSE
└─ README.md
```

## 安装与部署（仅安装包方式）

本项目对普通部署用户只推荐一种安装方式：**双击安装包安装项目文件 + 手动安装少量系统依赖 + 手动拉取 Ollama 模型 + 启动项目**。  
请严格按以下顺序执行，不要跳步骤。

### 1. 安装前准备（目标机器）

必须满足：

- Windows 10/11 或 Windows Server
- 已安装 Python 3.12（建议路径：`C:\python\python312\python.exe`）
- 已安装并运行 MySQL（你自己的地址、端口、账号、密码）
- 使用管理员权限操作（抓包相关步骤建议管理员 PowerShell）
- 服务器防火墙/云安全组已放行业务端口、前端端口和 API 端口，例如 `4000`、`1145`、`3049`

### 2. 双击安装包

安装包文件：

- `dist/JingyuanTrafficPipeline_Setup_ManualDeps.exe`

操作：

1. 双击 `JingyuanTrafficPipeline_Setup_ManualDeps.exe`
2. 按向导完成安装（默认安装目录通常为 `C:\JingyuanTrafficPipeline`）
3. 安装结束后，先不要直接测试抓包，先完成第 3 步依赖安装

### 3. 手动安装依赖（必须）

安装包安装完成后，进入目录：

- `C:\JingyuanTrafficPipeline\manual_installers\`

按顺序安装：

1. `npcap-1.82.exe`
2. `Wireshark_4.6.5_Machine_X64_nullsoft_zh-CN.exe`
3. `OllamaSetup.exe`

说明：

- `Npcap` 是抓包驱动，没装好会导致抓包看起来“运行正常但没有数据”。
- `Wireshark` 请确认包含 `tshark`/`dumpcap` 组件。
- `Ollama` 是大模型服务，后续 LLM 研判依赖它。
- 这些依赖属于系统级驱动/桌面程序，安装器会随项目提供安装包，但仍需要用户按向导手动确认安装。

### 4. 部署大模型（Ollama）

打开新终端执行：

```powershell
ollama list
```

如果命令不可用，重开终端再试。可用后执行：

```powershell
ollama pull qwen2.5:3b
ollama list
```

建议：

- 资源紧张机器：`qwen2.5:3b`
- 资源较充足机器：可换更大模型（例如 `qwen3:8b`），并在系统配置中对应修改
- 模型名必须和 `ollama list` 中显示的一致，例如 `qwen2.5:3b` 或 `qwen3:8b`

### 5. 配置数据库连接

编辑文件：

- `C:\JingyuanTrafficPipeline\config\db_config.json`

至少确认以下字段正确：

- `mysql.host`
- `mysql.port`
- `mysql.user`
- `mysql.password`
- `mysql.database`

首次启动时系统会自动初始化需要的业务表和默认账号；不会清空你已有的 MySQL 数据。

默认前端账号：

- 普通用户：`user / admin`
- 管理员：`admin / admin`

### 6. 启动项目（正式投用）

在项目目录执行（管理员 PowerShell）：

```powershell
cd C:\JingyuanTrafficPipeline
python app.py --mysql-port 3307 --port 4000 --capture-batch-size 1 --interface 4 --auto-start-lab
```

说明：

- `--port` 是抓包监听端口（示例为 `4000`）
- `--interface` 是抓包网卡编号（示例 `4` 通常是以太网）
- 如果你测试流量是“本机访问本机（127.0.0.1）”，请改成回环网卡编号（常见是 `5`）
- 如果已经在前端“系统配置”保存了端口、分组数量、网卡、模型，后续可直接执行 `python app.py`，系统会优先读取配置。
- 默认会同时启动 SSH 爆破监控，读取 Windows 登录失败事件并聚合为 `SSH爆破` 告警。
- 如测试环境没有 SSH/OpenSSH 日志，监控进程会安静运行，不影响 HTTP 抓包检测。
- 如需临时关闭 SSH 爆破监控，可追加：`--no-ssh-monitor`。
- `--auto-start-lab` 会由同一个主进程自动启动 `4000` 端口多漏洞靶场；如果 `4000` 已有靶场运行，会复用现有进程，不会重复启动。主系统停止时，由主进程启动的靶场也会一并停止。
- 生产环境不需要靶场时省略该参数；仅打开网页不会在操作系统层面创建进程，自动启动入口是统一启动命令/计划任务。

### 7. 启动靶场（测试用，可选）

正式测试建议直接使用上一节的统一命令和 `--auto-start-lab`。需要单独启动或手动恢复时，再使用下面的脚本：

```powershell
powershell -ExecutionPolicy Bypass -File C:\JingyuanTrafficPipeline\test\start_multivuln_lab_4000.ps1 -PythonExe C:\python\python312\python.exe -BindHost 0.0.0.0 -Port 4000
```

新版靶场首页提供“一键全链路模拟”，依次生成信息收集、凭据攻击、SQL 注入、XSS、Fastjson 公开风险特征和未知威胁结构等测试流量。Fastjson、Log4j、Spring、Shiro 模块只依据官方公开安全公告构造不可执行标记，不包含 Gadget、回连、文件写入或命令执行；未知威胁模块不宣称或复现任何未公开漏洞。

### 8. 验证是否可用

访问：

- 前端大屏：`http://127.0.0.1:1145`
- 后端 API：`http://127.0.0.1:3049`
- 测试靶场：`http://127.0.0.1:4000`

进入前端后建议：

1. 管理员登录
2. 打开“系统配置”
3. 执行“一键检查运行环境”
4. 确认：
- MySQL 连接成功
- 抓包依赖/tshark 正常
- 抓包网卡可枚举
- Ollama 服务正常
- 模型已安装
- 抓包探测成功

如果其中任何一项失败，先按页面提示修复，不要直接做攻击流量测试。

### 9. 如何投入正式使用

建议流程：

1. 按业务实际填写监测端口（如 `80,443,3000`）
2. 选择正确抓包网卡（外部流量一般选以太网）
3. 在低峰时段先进行 10~30 分钟灰度观察
4. 检查 `input/`、`result/`、大屏事件列表是否持续更新
5. 再切换到持续运行
6. 如需个性化展示，可在管理员“系统配置”上传主页背景图

### 10. 停止与重启

- 当前前台运行窗口：`Ctrl + C` 停止
- 停止靶场：

```powershell
powershell -ExecutionPolicy Bypass -File C:\JingyuanTrafficPipeline\test\stop_target_labs.ps1
```

### 11. 常见问题（安装包场景）

- 双击安装包后能打开页面但无攻击数据：
  - 先检查 `Npcap` 和 `Wireshark` 是否真的安装完成
  - 检查网卡是否选错（本机回环流量与外部流量网卡不同）
- `ollama` 命令不存在：
  - 重新打开终端，或重启系统后再试
- LLM 无结果：
  - 执行 `ollama list` 确认模型存在
  - 在系统配置里确认模型名与已安装模型一致
- MySQL 连不上：
  - 检查 `config/db_config.json` 与实际数据库参数是否一致

## Workflow

1. `scripts/capture_http_request_batches.py`
2. `input/1.1.n.txt`
3. `scripts/run_demo_daemon.py`
4. `scripts/demo_workflow.py`
   - `extract_old_model_features_from_txt.py`
   - `run_old_model_direct.py`
   - `rerank_model_result.py`
   - `build_demo_candidates.py`
   - `export_demo_candidates_to_result.py`
   - Detection V2 gate 默认启用，先判定 `raw_only/candidate/attack_event`
5. `result/b.n`
6. `scripts/llm_analyzer_daemon.py` reads `result/b.n` and writes:
   - `result/b.n/analysis.json`
   - `result/b.n/analysis_raw.txt`
7. `scripts/result_db_daemon.py` watches `result/b.n` and upserts into:
   - default MySQL: `traffic_pipeline` (127.0.0.1:3306, root/123456)
   - sqlite fallback: `result/result_cases.db`
   - legacy tables: `requests`, `responses`, `analyses`, `demo_attack_events`
   - v2 tables: `raw_http_logs`, `detection_candidates`, `attack_events`, `model_predictions`, `poc_matches`, `behavior_windows`
   - 同时监听 `input/1.1.n.txt`，实现原始 HTTP 日志全量入库
8. `scripts/dashboard_api_server.py` serves frontend query API on `:3049`

## Frontend API

- `GET /api/v1/screen/ping`
- `GET /api/v1/screen/attacks?limit=100&offset=0&llm_status=done`
- `GET /api/v1/screen/request-body?case_id=b.11`
- `GET /api/v1/screen/request-body?file_id=1.1.302&seq_id=1`
- `GET /api/v1/screen/response-body?case_id=b.11`
- `GET /api/v1/screen/response-body?file_id=1.1.302&seq_id=1`

`analyses` optimized fields for dashboard:

- `attack_event_time`: attack/detection time
- `attack_ip`: source attacker ip
- `target_interface`: attacked endpoint/interface
- `attack_type`: attack type
- `attack_confidence`: confidence score

## AI Platform API (v2, MySQL Demo)

Start API only (with demo seed):

```powershell
python scripts\dashboard_api_server.py --port 3049 --seed-demo
```

For API integration, use the current `/api/v2` and `/api/v3` declarations in `docs/API_DECLARATION.md`.

Demo login accounts (frontend hard-coded):

- 普通用户：`user / admin`
- 管理员：`admin / admin`
- role is decided by the selected identity button on login page

Auth:

- `GET /api/v2/auth/demo-accounts`
- `POST /api/v2/auth/register` (register normal user and return JWT)
- `POST /api/v2/auth/login`
- `POST /api/v2/auth/logout`
- `GET /api/v2/auth/profile`
- `POST /api/v2/auth/change-password`

Auth note:

- v2 uses JWT Bearer token (`Authorization: Bearer <token>`)

Plugins:

- `POST /api/v2/plugins/phishing/check`

Event handling:

- `POST /api/v2/pro/events/{event_id}/block-ip`

Common:

- `GET /api/v2/common/system-status`
- `GET /api/v2/common/alerts/ticker?limit=3`
- `POST /api/v2/common/alerts/{event_id}/ack`

Normal user dashboard:

- `GET /api/v2/user/dashboard/kpis`
- `GET /api/v2/user/dashboard/trend7d`
- `GET /api/v2/user/dashboard/top-attack-types`
- `GET /api/v2/user/dashboard/source-distribution`
- `GET /api/v2/user/dashboard/heatmap`
- `GET /api/v2/user/dashboard/method-share`

Details view:

- `GET /api/v2/pro/events?time_range=24h&page=1&page_size=20`
- `GET /api/v2/pro/events/{event_id}`
- `GET /api/v2/pro/candidates?page=1&page_size=20&q=`
- `GET /api/v2/pro/candidates/{event_id}`
- `POST /api/v2/pro/candidates/{event_id}/promote`
- `POST /api/v2/pro/candidates/{event_id}/ignore`
- `GET /api/v2/pro/nodes/{node_name}/detail`

Situation awareness and professional reports:

- `GET /api/v2/situations`
- `GET /api/v2/situations/{situation_id}`
- `POST /api/v2/situations/{situation_id}/professional-report`
- `GET /api/v2/situations/{situation_id}/professional-report`
- `GET /api/v2/situations/{situation_id}/professional-report/download?job_id=...`
- `GET /api/v2/llm/professional-report-prompt` (administrator)
- `PUT /api/v2/llm/professional-report-prompt` (administrator)

Professional reports run asynchronously. The browser can leave the progress dialog and retrieve the same job later. Report files are stored outside the project runtime directory when `SITUATION_REPORT_DIR` is configured (the server currently uses `D:/JingyuanTrafficPipelineData/reports`).

Admin:

- `GET /api/v2/admin/summary`
- `GET /api/v2/admin/machines/ranking`
- `GET /api/v2/admin/trend7d`
- `GET /api/v2/admin/machines`
- `GET /api/v2/admin/machines/{machine_id}`
- `POST /api/v2/admin/machines/{machine_id}/restart-service`
- `GET /api/v2/admin/user-op-logs?page=1&page_size=30`
- `GET /api/v2/admin/config`
- `PUT /api/v2/admin/config`
- `GET /api/v2/admin/users`
- `PUT /api/v2/admin/users/{username}/password`
- `GET /api/v2/rag/docs`
- `POST /api/v2/rag/docs`
- `POST /api/v2/rag/docs/{doc_id}/delete`
- `POST /api/v2/rag/rebuild`
- `POST /api/v2/pro/events/batch-status`
- `POST /api/v2/pro/events/{event_id}/note`
- `GET /api/v2/pro/model/performance`
- `GET /api/v2/admin/reports/export`

## Logs and State

- App runtime logs: `output/app_runtime/`
- Daemon state: `output/demo_daemon_state.json`
- Per-run logs: `output/daemon_runs/`
- LLM runtime logs: `output/app_runtime/llm_stdout.log`, `output/app_runtime/llm_stderr.log`
- DB runtime logs: `output/app_runtime/db_stdout.log`, `output/app_runtime/db_stderr.log`
- DB daemon state/log: `output/result_db_daemon_state.json`, `output/result_db_daemon.log`
- Supervisor heartbeat: `output/app_runtime/app_state.json`
- Durable capture-to-pipeline queue: `output/pipeline_events/input_events.jsonl`

The main supervisor restarts an individual failed capture, database, API, dashboard, LLM, SSH, situation, or lab process without stopping the other healthy services. `install_watchdog.ps1` installs the Windows scheduled health check; `watchdog.ps1` only replaces the full process tree after the supervisor has remained unhealthy for three minutes.

## LLM Directory

- `llm/prompts/system_prompt.txt`: system prompt
- `llm/schemas/analysis.schema.json`: output schema
- `llm/README.md`: LLM usage notes

## 项目状态与规划

- [x] Automated capture and batch generation
- [x] Automated detection daemon
- [x] Structured suspicious case export
- [ ] 双 LLM 协同研判（当前主链路为兼容模型 + 单 LLM）
- [ ] Structured outputs: source IP, target IP, attack type, path, time, target
- [x] 前端态势感知大屏与后台管理页面
- [x] Database persistence and querying

## Responsible Use

Use only in authorized environments for defense, testing, and research.

## Docs

- Main guide: `docs/PROJECT_GUIDE.md`
- Usage guide: `docs/USAGE.md`
- Windows prerequisite setup: `docs/WINDOWS_PREREQ_SETUP.md`
- API declaration: `docs/API_DECLARATION.md`
- Monthly changelog: `docs/CHANGELOG_2026-04_2026-05.md`
- Contribution guide: `CONTRIBUTING.md`
- Security policy: `SECURITY.md`

## Test Targets

- Recommended multi-vuln target (port 4000):
  - `test/start_multivuln_lab_4000.ps1`
  - `test/start_multivuln_lab_4000.bat`
- Stop targets:
  - `test/stop_target_labs.ps1`

## Manual Installers (Windows)

If your server cannot install all dependencies automatically, use:

- `manual_installers/npcap-1.82.exe`
- `manual_installers/Wireshark_4.6.5_Machine_X64_nullsoft_zh-CN.exe`
- `manual_installers/OllamaSetup.exe`

After installing Ollama, pull model:

```bash
ollama pull qwen2.5:3b
```

`deploy/start_all_nodocker.ps1` will prefer installers in `manual_installers/` when available.

## Troubleshooting

- Symptom: `input` has files but `result` is empty.
  - Check `output/app_runtime/daemon_stdout.log` and `output/daemon_runs/*.log`.
  - If you see `preprocessor.joblib` / `best_mlp.pth` not found, ensure these files exist:
    - `models/preprocessor.joblib`
    - `models/best_mlp.pth`

- Symptom: local self-test to `127.0.0.1:4000` is not captured.
  - Use loopback interface in admin config (`capture_interface=5` on most Windows hosts).
  - For real external traffic to server NIC, switch back to Ethernet interface (for example `4`).

## License

MIT

