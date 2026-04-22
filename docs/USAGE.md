# 使用文档（部署与运行）

## 1. 项目说明

本项目提供完整的攻击检测与态势感知链路，包含：

- 检测守护（读取 `input/`，产出 `result/`）
- 结果入库守护（MySQL/SQLite）
- Flask API（默认 `3049`）
- Node 大屏服务（默认 `1145`）
- RAG 知识库管理（前端可新增/删除/重建）

说明：Docker 一键部署默认不启动 LLM（按当前需求）。

## 2. 目录结构（关键）

- `app.py`：统一启动入口
- `scripts/dashboard_api_server.py`：后端接口服务
- `frontend_dashboard/`：前端大屏
- `config/db_config.json`：本机数据库配置
- `config/db_config.docker.json`：Docker 场景数据库配置
- `docker-compose.yml`：一键部署编排

## 3. 环境准备

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

前端演示账号统一：`admin / admin`

身份由登录页角色按钮决定：

- 普通用户（normal）
- 专业用户（pro）
- 管理员（admin）

登录后推荐页面结构：

- 数据大屏
- 详情信息
- RAG数据库设置
- （管理员附加）全局概览 / 操作日志 / 系统配置

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
- 数据为空：检查 `result/` 是否有新 case，及 DB 守护是否正常运行
- MySQL 连接失败：检查 `config/db_config*.json` 中 host/port/user/password/database
