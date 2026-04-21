# JingYuan: Dual-LLM Threat Detection

JingYuan is a dual-LLM-driven network attack detection and situation awareness system.

Current stage focuses on an end-to-end automated pipeline:

- Capture HTTP traffic from a selected network interface and TCP port
- Build canonical batch files (`input/1.1.n.txt`) from complete request/response pairs
- Auto-detect newly arrived batches
- Run compatibility inference pipeline
- Export suspicious cases into `result/b.n` for downstream LLM analysis and frontend visualization

## Repository

Recommended repo name: `jingyuan-dual-llm-threat-detection`

## Key Features

- Single entry point: `app.py`
- Configurable port monitoring (`80`, `3000`, `10086`, etc.)
- Batch by complete HTTP request/response records (not raw packet slicing)
- Automatic detection daemon for new input files
- Structured case export for downstream analysis

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

1. Install dependencies:

```powershell
python -m pip install -r requirements.txt
```

2. Start the full workflow (capture + detect + LLM + DB + API + Dashboard):

```powershell
python app.py --port 80 --capture-batch-size 4
```

For local demo (one-command startup, without packet capture):

```powershell
python app.py --only-detect --no-llm --db-backend mysql --mysql-host 127.0.0.1 --mysql-port 3306 --mysql-user root --mysql-password 123456 --mysql-database traffic_pipeline --api-port 3049 --dashboard-port 1145
```

Use DB config file (recommended):

```powershell
python app.py --only-detect --no-llm --db-config config/db_config.json --api-port 3049 --dashboard-port 1145
```

3. Show all options:

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

## Docker One-Click Deploy (No LLM)

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

Disable LLM in unified app entry:

```powershell
python app.py --no-llm
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

- normal user: `admin / admin`
- pro user: `admin / admin`
- admin user: `admin / admin`
- role is decided by the selected identity button on login page

Auth:

- `GET /api/v2/auth/demo-accounts`
- `POST /api/v2/auth/login`
- `POST /api/v2/auth/logout`
- `GET /api/v2/auth/profile`

Common:

- `GET /api/v2/common/system-status`
- `GET /api/v2/common/alerts/ticker?limit=3`
- `GET /api/v2/common/alerts/popup?limit=5`
- `POST /api/v2/common/alerts/{event_id}/ack`

Normal user dashboard:

- `GET /api/v2/user/dashboard/kpis`
- `GET /api/v2/user/dashboard/trend7d`
- `GET /api/v2/user/dashboard/top-attack-types`
- `GET /api/v2/user/dashboard/source-distribution`
- `GET /api/v2/user/dashboard/heatmap`
- `GET /api/v2/user/dashboard/method-share`

Pro user:

- `GET /api/v2/pro/events?time_range=24h&page=1&page_size=20`
- `GET /api/v2/pro/events/{event_id}`
- `POST /api/v2/pro/events/batch-status`
- `POST /api/v2/pro/events/{event_id}/note`
- `GET /api/v2/pro/model/performance`
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

## Roadmap

- [x] Automated capture and batch generation
- [x] Automated detection daemon
- [x] Structured suspicious case export
- [ ] Dual-LLM inference layer for threat explanation
- [ ] Structured outputs: source IP, target IP, attack type, path, time, target
- [ ] Frontend situation awareness dashboards
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
