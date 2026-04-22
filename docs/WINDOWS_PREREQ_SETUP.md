# Windows 前置安装与手动部署说明（一键部署之外）

本文档专门说明：在一台陌生 Windows 机器上，哪些内容需要先手动准备，为什么一键脚本做不到，以及如何完整安装。

## 1. 一键脚本能做什么，不能做什么

`deploy/start_all.ps1` 能自动完成：

- 拉起 MySQL 容器（业务库）
- 拉起 Ollama 容器并拉取模型
- 构建 SQLite RAG 库（`llm/rag/rag_knowledge.db`）
- 安装 Python 依赖
- 启动项目全链路服务（抓包/检测/入库/API/前端）

一键脚本做不到（必须手动）：

- 安装系统级软件：Docker Desktop、Python、Node.js、Wireshark/Npcap、Git
- BIOS/Windows 虚拟化能力开启（Docker 依赖）
- 抓包驱动与权限授权（Npcap、管理员权限、防火墙）
- 网络代理/证书配置（模型拉取依赖外网时）

## 2. 前置软件安装（建议顺序）

## 2.1 Git

安装后验证：

```powershell
git --version
```

## 2.2 Docker Desktop（必须）

用途：一键脚本通过 Docker 启动 MySQL 和 Ollama。

安装后验证：

```powershell
docker --version
docker compose version
docker info
```

若 `docker info` 报错，先启动 Docker Desktop，再重试。

## 2.3 Python 3.10+（必须）

安装时勾选 `Add python.exe to PATH`。

验证：

```powershell
python --version
python -m pip --version
```

## 2.4 Node.js 18+（必须）

用途：前端大屏服务 `frontend_dashboard/server.js`。

验证：

```powershell
node -v
npm -v
```

## 2.5 Wireshark + Npcap（抓包必须）

用途：项目抓包脚本依赖 `tshark`（Wireshark 命令行工具）。

安装建议：

- 安装 Wireshark 时勾选 `TShark`
- 安装 Npcap（通常会随 Wireshark 安装流程引导）
- 抓包时建议用管理员 PowerShell 启动项目

验证：

```powershell
tshark -v
tshark -D
```

说明：

- `tshark -D` 能列出网卡即表示抓包环境基本正常
- 若找不到 `tshark`，请把 Wireshark 安装目录加入 PATH，或重开终端

## 3. 两个数据库的部署与说明

## 3.1 业务数据库：MySQL（必须）

推荐方式（与一键脚本一致）：Docker 容器部署。

```powershell
docker run -d --name traffic_pipeline_mysql `
  -e MYSQL_ROOT_PASSWORD=123456 `
  -e MYSQL_DATABASE=traffic_pipeline `
  -p 3306:3306 `
  mysql:8.0
```

连通性验证：

```powershell
docker exec traffic_pipeline_mysql mysqladmin ping -h 127.0.0.1 -uroot -p123456 --silent
docker exec traffic_pipeline_mysql mysql -uroot -p123456 -e "SHOW DATABASES;"
```

你也可以使用本机安装版 MySQL（非 Docker），但要保证以下与配置一致：

- Host: `127.0.0.1`
- Port: `3306`
- User: `root`
- Password: `123456`（或你自定义后同步到配置文件）
- Database: `traffic_pipeline`

## 3.2 RAG 数据库：SQLite FTS5（必须）

RAG 库文件：`llm/rag/rag_knowledge.db`

这是一个本地 SQLite 文件库，不需要安装额外数据库服务。可手动重建：

```powershell
python scripts/build_rag_db.py --seed-file llm/rag/rag_seed.json --db-path llm/rag/rag_knowledge.db
```

验证文件是否生成：

```powershell
Test-Path llm/rag/rag_knowledge.db
```

## 4. Ollama 与模型部署

## 4.1 方案 A：Docker 方式（推荐，与一键一致）

```powershell
docker run -d --name traffic_pipeline_ollama -p 11434:11434 ollama/ollama:latest
curl http://127.0.0.1:11434/api/tags
```

拉取模型（示例 `qwen3:8b`）：

```powershell
curl -Method Post http://127.0.0.1:11434/api/pull `
  -ContentType "application/json" `
  -Body '{"model":"qwen3:8b","stream":false}'
```

## 4.2 方案 B：本机安装 Ollama（可选）

若你不走 Docker，可在本机安装 Ollama，并手动启动：

```powershell
ollama --version
ollama serve
```

新开终端拉模型：

```powershell
ollama pull qwen3:8b
ollama list
```

可选：将模型目录放到 D 盘（重启终端后生效）：

```powershell
setx OLLAMA_MODELS "D:\\ollama\\models"
```

## 5. 新机器最小验收清单（建议逐条执行）

```powershell
git --version
docker --version
docker compose version
python --version
node -v
tshark -v
tshark -D
```

如果以上都通过，再执行项目一键部署：

```powershell
powershell -ExecutionPolicy Bypass -File deploy/start_all.ps1
```

## 6. 项目一键部署后的验证

检查端口：

```powershell
netstat -ano | findstr ":1145"
netstat -ano | findstr ":3049"
netstat -ano | findstr ":3306"
netstat -ano | findstr ":11434"
```

健康检查：

```powershell
Invoke-WebRequest http://127.0.0.1:3049/api/v1/screen/ping
Invoke-WebRequest http://127.0.0.1:1145
curl http://127.0.0.1:11434/api/tags
```

## 7. 常见问题与处理

1. `docker command not found`

- Docker Desktop 未安装或未启动
- 重开终端后重试

2. `tshark` 不存在或抓不到包

- 未安装 Wireshark/Npcap，或未勾选 TShark
- 终端非管理员权限
- 监听端口/网卡配置错误（前端系统配置里改了端口后，需确认流量确实走该端口）

3. Ollama 拉模失败

- 网络受限或镜像拉取超时
- 先确认 `curl http://127.0.0.1:11434/api/tags` 可访问，再重试 pull

4. MySQL 连接失败

- 端口占用或密码不一致
- 核对 `deploy/.env`、`config/db_config.json` 与实际服务一致

5. 前端有页面但无数据

- 抓包环节没抓到目标端口流量
- `result/` 没有新增 case
- `result_db_daemon` 未正常写入 `analyses/requests/responses`

## 8. 推荐部署顺序（总结）

1. 安装 Docker/Python/Node/Git/Wireshark+Npcap  
2. 跑一遍“最小验收清单”  
3. 执行 `deploy/start_all.ps1`  
4. 在前端系统配置里确认监听端口  
5. 发送测试流量并观察大屏/详情/API 是否同步刷新
