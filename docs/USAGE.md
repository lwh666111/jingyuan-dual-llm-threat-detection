# 使用文档（部署与运行）

## 0. 最新版本快速使用（2026-08-04）

### 0.1 直接安装（推荐）

1. 运行安装包：`dist/JingyuanTrafficPipeline_Setup_ManualDeps.exe`
2. 首次部署后，进入项目目录执行：

```powershell
cd C:\JingyuanTrafficPipeline
python app.py --mysql-port 3307 --port 4000 --capture-batch-size 1 --interface 4
```

3. 启动多漏洞靶场（测试用）：

```powershell
powershell -ExecutionPolicy Bypass -File C:\JingyuanTrafficPipeline\test\start_multivuln_lab_4000.ps1 -PythonExe C:\python\python312\python.exe -BindHost 0.0.0.0 -Port 4000
```

进入靶场后可按“信息收集、经典漏洞、N-day 特征模拟、未知威胁模拟”逐项测试，也可点击“一键全链路模拟”顺序发送 7 个阶段化动作。N-day 与未知威胁页面都是安全检测样本生成器，不会执行利用代码。

4. 访问：

- 前端：`http://127.0.0.1:1145`
- API：`http://127.0.0.1:3049`
- 靶场：`http://127.0.0.1:4000`

### 0.2 管理员系统配置建议

- 在“系统配置”页面执行“一键检查运行环境”。
- 监测端口与靶场端口保持一致（例如靶场在 `4000`，监测端口也应为 `4000`）。
- 外部机器压测服务器时，抓包网卡使用业务网卡（如以太网）；服务器本机回环测试时改为回环网卡。


### 0.3 2026-07-01 版本重点

- Detection V2 已接入全链路：原始日志全量入库，候选事件进入复核队列，高置信攻击进入大屏。
- 正常账号密码登录不会因为访问 `/login` 或包含 username/password 字段就进入告警。
- SQL 注入、XSS、命令注入、路径遍历、危险上传等经典攻击继续保持高召回。
- 行为窗口模型可辅助识别暴力破解、扫描、目录探测、高频请求。
- 管理员“详情信息”页面支持候选事件查看、提升、忽略。
- 安装包仍位于 `dist/JingyuanTrafficPipeline_Setup_ManualDeps.exe`。

### 0.4 连续攻击态势

- 启动 `python app.py` 后，态势关联、AI 报告和端口扫描传感器默认随主程序启动。
- 登录后点击顶部“态势感知展示”，可按攻击者查看扫描、爆破和漏洞利用的连续链路。
- 管理员可在“系统配置”调整动作种类阈值、关联窗口、静默切段和扫描阈值；保存后守护进程会自动应用。
- 默认至少需要同一来源、同一目标在窗口内出现 3 类不同动作，不足阈值时页面没有正式态势属于正常情况。
- 可选 Neo4j 仅用于图镜像，不安装也不影响 MySQL、API 和前端。启用方式见 `docs/SITUATION_INTELLIGENCE.md`。
- 链路默认使用“聚合视图”，连续同类动作和过长序列会合并，避免几十个节点互相遮挡；需要逐条核查时切换到“证据视图”。
- 新生成的 AI 报告会详细覆盖时间线、技术路径、证据强度、影响与失陷判断、调查和处置建议；旧报告仍可兼容展示，管理员点击“重新研判”即可按新结构生成。
## 1. 项目说明

本项目提供完整的攻击检测与态势感知链路，包含：

- 检测守护（读取 `input/`，产出 `result/`）
- 结果入库守护（MySQL/SQLite）
- Flask API（默认 `3049`）
- Node 大屏服务（默认 `1145`）
- RAG 知识库管理（前端可新增/删除/重建）

说明：正式交付推荐使用安装包方式部署；Docker/脚本方式保留给开发和调试场景。

## 2. 目录结构（关键）

- `app.py`：统一启动入口
- `scripts/dashboard_api_server.py`：后端接口服务
- `frontend_dashboard/`：前端大屏
- `config/db_config.json`：本机数据库配置
- `config/db_config.docker.json`：Docker 场景数据库配置
- `docker-compose.yml`：一键部署编排

## 3. 环境准备

首次在陌生 Windows 机器部署时，先看：

- `docs/WINDOWS_PREREQ_SETUP.md`（Docker/Python/Node/Wireshark+Npcap/Ollama/MySQL/RAG 全步骤）

### 3.1 本机运行

- Python 3.10+
- Node.js 18+
- MySQL 8+

安装依赖：

```powershell
python -m pip install -r requirements.txt
```

### 3.2 Docker 运行

- Docker Desktop（含 Compose）

## 4. 数据库配置文件

### 4.1 本机配置

文件：`config/db_config.json`

```json
{
  "db_backend": "mysql",
  "db_path": "result/result_cases.db",
  "mysql": {
    "host": "127.0.0.1",
    "port": 3306,
    "user": "root",
    "password": "123456",
    "database": "traffic_pipeline"
  }
}
```

### 4.2 Docker 配置

文件：`config/db_config.docker.json`（容器内通过服务名 `mysql` 连接）

```json
{
  "db_backend": "mysql",
  "db_path": "result/result_cases.db",
  "mysql": {
    "host": "mysql",
    "port": 3306,
    "user": "root",
    "password": "123456",
    "database": "traffic_pipeline"
  }
}
```

说明：CLI 参数优先级高于配置文件参数。

## 5. 启动方式

### 5.0 全链路一键部署（推荐）

首次执行（生成配置模板）：

```powershell
powershell -ExecutionPolicy Bypass -File deploy/start_all.ps1
```

编辑 `deploy/.env` 后正式启动：

```powershell
powershell -ExecutionPolicy Bypass -File deploy/start_all.ps1
```

说明：

- 自动部署 MySQL（业务库）
- 自动构建 SQLite RAG 库（`llm/rag/rag_knowledge.db`）
- 自动部署 Ollama，并拉取 `deploy/.env` 中配置的模型
- 自动启动 `app.py` 全链路服务（抓包/检测/入库/API/前端）

停止服务：

```powershell
powershell -ExecutionPolicy Bypass -File deploy/stop_all.ps1
```

停止并清理 MySQL/Ollama 数据卷：

```powershell
powershell -ExecutionPolicy Bypass -File deploy/stop_all.ps1 -RemoveInfraData
```

### 5.1 本机一键启动（不启 LLM）

```powershell
python app.py --only-detect --no-llm --db-config config/db_config.json --api-port 3049 --dashboard-port 1145
```

### 5.1.1 本机启动并启用 LLM + RAG

```powershell
python app.py --only-detect --enable-llm --rag-enable --rag-db-path llm/rag/rag_knowledge.db --rag-top-k 3 --db-config config/db_config.json --api-port 3049 --dashboard-port 1145
```

### 5.2 Docker 一键启动（不启 LLM）

```powershell
docker compose up -d --build
```

停止：

```powershell
docker compose down
```

## 6. RAG 知识库

- 构建脚本：`scripts/build_rag_db.py`
- 种子数据：`llm/rag/rag_seed.json`
- 生成库：`llm/rag/rag_knowledge.db`

手动构建：

```powershell
python scripts/build_rag_db.py --seed-file llm/rag/rag_seed.json --db-path llm/rag/rag_knowledge.db
```

说明：

- 采用 SQLite FTS5，部署成本低，无需额外向量服务
- `llm_analyzer_daemon.py` 会把检索到的 top-k 知识条目注入到 LLM 上下文
- 默认启用自动构建（db 不存在时按 seed 自动生成）

## 7. 访问地址

- 前端大屏：`http://127.0.0.1:1145`
- 后端 API：`http://127.0.0.1:3049`
- MySQL：`127.0.0.1:3306`

## 8. 登录账号

前端演示账号：

- 普通用户：`user / admin`
- 管理员：`admin / admin`

身份由登录页角色按钮决定：

- 普通用户（normal）
- 管理员（admin）

登录后推荐页面结构：

- 数据大屏
- 详情信息
- 用户中心（可改密码）
- （管理员附加）RAG数据库设置 / 全局概览 / 操作日志 / 系统配置 / 管理用户

## 9. 快速自检

### 9.1 接口可用性

```powershell
Invoke-WebRequest http://127.0.0.1:3049/api/v1/screen/ping
```

### 9.2 API 联调脚本

```powershell
python scripts/platform_api_demo.py
```

## 10. 运行日志与排障

- 总控日志：`output/app_runtime/app.log`
- API 日志：`output/app_runtime/api_stdout.log`、`output/app_runtime/api_stderr.log`
- DB 守护：`output/app_runtime/db_stdout.log`、`output/app_runtime/db_stderr.log`
- 检测守护：`output/app_runtime/daemon_stdout.log`、`output/app_runtime/daemon_stderr.log`

常见问题：

- 1145 打不开：检查 Node 是否启动、端口是否被占用
- 3049 无响应：检查 Flask 子进程日志
- 数据为空：先检查 `input/` 是否有新批次；如果只有正常访问，大屏不会出现攻击事件，可在数据库 `raw_http_logs` 中查看原始日志；再检查 `result/` 是否有高置信 case，及 DB 守护是否正常运行
- MySQL 连接失败：检查 `config/db_config*.json` 中 host/port/user/password/database



