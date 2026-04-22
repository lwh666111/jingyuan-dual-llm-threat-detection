# 靖渊 AI 攻击态势感知平台

面向实战流量的端到端安全分析系统，覆盖抓包、检测、LLM 研判、RAG 增强、结果入库、API 服务与前端大屏。

当前版本核心链路：

- 监听指定网卡和端口，抓取完整 HTTP 请求/响应
- 生成标准化批次文件（`input/1.1.n.txt`）
- 自动化检测与可疑事件导出（`result/b.n`）
- Ollama 大模型研判 + SQLite FTS5 RAG 检索增强
- MySQL 持久化（`requests` / `responses` / `analyses` 三表）
- Flask API（3049）+ Node 前端大屏（1145）

## GitHub 仓库简介（中文建议）

可直接粘贴到 GitHub 仓库 Description：

`靖渊 AI 攻击态势感知平台：支持真实抓包、自动检测、Ollama+RAG 研判、MySQL 入库与大屏展示，已支持一键部署（MySQL + Ollama + 全链路服务）。`

## 主要能力

- 统一入口：`app.py`
- 一键部署：`deploy/start_all.ps1`（MySQL + Ollama + RAG + 全链路服务）
- 可配置多端口监听（如 `80,3000,10086`）
- 基于完整 HTTP 请求/响应配对的批次采集（非原始切片）
- 自动检测守护 + LLM 研判守护 + 自动入库守护
- 前端角色权限：普通用户 / 管理员
- RAG 文档管理接口：新增、删除、重建

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

## Quick Start

默认使用一键部署，不再需要手工“下库”或分别启动多服务。

1. 首次执行（自动生成 `deploy/.env` 模板）：

```powershell
powershell -ExecutionPolicy Bypass -File deploy/start_all.ps1
```

2. 按需修改 `deploy/.env`（模型、端口、数据库密码等）后再次执行：

```powershell
powershell -ExecutionPolicy Bypass -File deploy/start_all.ps1
```

3. 访问服务：

- 前端大屏：`http://127.0.0.1:1145`
- API：`http://127.0.0.1:3049`
- Ollama：`http://127.0.0.1:11434`

4. 停止服务：

```powershell
powershell -ExecutionPolicy Bypass -File deploy/stop_all.ps1
```

## One-Click Full Deploy (Recommended)

This project now supports one-click deployment for:

- MySQL database (business/event data)
- SQLite FTS5 RAG database (`llm/rag/rag_knowledge.db`)
- Ollama service and model pull
- Python runtime dependencies
- Unified app services (`capture + daemon + db + api + dashboard`)

Steps:

1. First run (generate env template):

```powershell
powershell -ExecutionPolicy Bypass -File deploy/start_all.ps1
```

2. Edit `deploy/.env` if needed (ports, model, DB password), then run:

```powershell
powershell -ExecutionPolicy Bypass -File deploy/start_all.ps1
```

Stop services:

```powershell
powershell -ExecutionPolicy Bypass -File deploy/stop_all.ps1
```

Stop and remove infra data volumes:

```powershell
powershell -ExecutionPolicy Bypass -File deploy/stop_all.ps1 -RemoveInfraData
```

## Manual Mode (Optional / Advanced)

以下仅用于调试或兼容场景，日常推荐使用一键部署：

Install dependencies:

```powershell
python -m pip install -r requirements.txt
```

Start the full workflow (capture + detect + LLM + DB + API + Dashboard):

```powershell
python app.py --port 80 --capture-batch-size 4
```

Local demo (without packet capture):

```powershell
python app.py --only-detect --no-llm --db-backend mysql --mysql-host 127.0.0.1 --mysql-port 3306 --mysql-user root --mysql-password 123456 --mysql-database traffic_pipeline --api-port 3049 --dashboard-port 1145
```

Use DB config file:

```powershell
python app.py --only-detect --no-llm --db-config config/db_config.json --api-port 3049 --dashboard-port 1145
```

Show all options:

```powershell
python app.py --help
```

## Database Config File

- local config: `config/db_config.json`
- docker config: `config/db_config.docker.json`
- CLI has higher priority than config file values

Format:

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

## Legacy Docker App-Only Deploy (No LLM)

This deployment includes:

- MySQL 8.0
- API service (`3049`)
- Dashboard frontend (`1145`)
- DB auto-ingest daemon
- Detection daemon

LLM is intentionally disabled in one-click Docker startup.

Start:

```powershell
docker compose up -d --build
```

Stop:

```powershell
docker compose down
```

Open dashboard:

- `http://127.0.0.1:1145`

## Common Commands

Listen on port 3000:

```powershell
python app.py --port 3000 --capture-batch-size 1
```

Capture only:

```powershell
python app.py --only-capture --port 80
```

Detect only:

```powershell
python app.py --only-detect --no-skip-existing-at-start
```

Detect only (without LLM):

```powershell
python app.py --only-detect --no-llm
```

Detect only (without LLM and DB):

```powershell
python app.py --only-detect --no-llm --no-db
```

Run LLM analysis daemon (file-output mode, no DB):

```powershell
python scripts\llm_analyzer_daemon.py --once --model qwen3:8b --num-gpu 0
python scripts\llm_analyzer_daemon.py --model qwen3:8b --num-gpu 0
```

Build RAG knowledge DB (SQLite FTS5):

```powershell
python scripts\build_rag_db.py --seed-file llm/rag/rag_seed.json --db-path llm/rag/rag_knowledge.db
```

Run LLM daemon with RAG enabled:

```powershell
python scripts\llm_analyzer_daemon.py --model qwen3:8b --rag-enable --rag-db-path llm/rag/rag_knowledge.db --rag-top-k 3
```

Disable LLM in unified app entry:

```powershell
python app.py --no-llm
```

RAG controls in unified app entry (effective when LLM enabled):

```powershell
python app.py --rag-enable --rag-db-path llm/rag/rag_knowledge.db --rag-top-k 3
```

Run DB sync daemon:

```powershell
python scripts\result_db_daemon.py --once
python scripts\result_db_daemon.py
# sqlite fallback:
python scripts\result_db_daemon.py --backend sqlite --db-path result/result_cases.db
```

Run frontend API service (Flask, port 3049):

```powershell
python scripts\dashboard_api_server.py --port 3049
```

Run Node.js dashboard (port 1145):

```powershell
node frontend_dashboard\server.js
```

Disable DB daemon in unified app entry:

```powershell
python app.py --no-db
```

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
5. `result/b.n`
6. `scripts/llm_analyzer_daemon.py` reads `result/b.n` and writes:
   - `result/b.n/analysis.json`
   - `result/b.n/analysis_raw.txt`
7. `scripts/result_db_daemon.py` watches `result/b.n` and upserts into:
   - default MySQL: `traffic_pipeline` (127.0.0.1:3306, root/123456)
   - sqlite fallback: `result/result_cases.db`
   - tables: `requests`, `responses`, `analyses`
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

Run API demo checker:

```powershell
python scripts\platform_api_demo.py
```

Demo login accounts (frontend hard-coded):

- 普通用户：`user / admin`
- 管理员：`admin / admin`
- role is decided by the selected identity button on login page

Auth:

- `GET /api/v2/auth/demo-accounts`
- `POST /api/v2/auth/login`
- `POST /api/v2/auth/logout`
- `GET /api/v2/auth/profile`
- `POST /api/v2/auth/change-password`

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
- `GET /api/v2/pro/nodes/{node_name}/detail`

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
- API declaration: `docs/API_DECLARATION.md`
- Contribution guide: `CONTRIBUTING.md`
- Security policy: `SECURITY.md`

## License

MIT
