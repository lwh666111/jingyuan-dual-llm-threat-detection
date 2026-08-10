# 接口声明（API Declaration）

版本：`v1 + v2`

## 1. 基础信息

- Base URL（默认）：`http://127.0.0.1:3049`
- 协议：HTTP/JSON
- 编码：UTF-8
- 鉴权：Bearer Token（v2）

请求头：

- `Content-Type: application/json`
- `Authorization: Bearer <token>`（v2 需要鉴权的接口）

## 2. 认证与角色

### 2.1 登录（JWT）

`POST /api/v2/auth/login`

请求体：

```json
{
  "username": "admin",
  "password": "admin",
  "role": "normal"
}
```

`role` 可选值：`normal | admin`。
建议传 `role`，避免同用户名场景下角色歧义。

响应示例：

```json
{
  "token": "xxx",
  "expires_in": 43200,
  "role": "normal",
  "display_name": "普通用户",
  "username": "user"
}
```

说明：

- `token` 为 JWT（HS256）
- 默认有效期 `12` 小时（可通过 API 启动参数调整）
- 调用需要鉴权的 v2 接口时，在请求头携带：
  - `Authorization: Bearer <token>`

### 2.2 注册（普通用户）

`POST /api/v2/auth/register`

请求体示例：

```json
{
  "username": "test_user01",
  "password": "abc12345",
  "display_name": "测试账号",
  "role": "normal"
}
```

约束：

- 仅允许注册 `normal` 角色
- 用户名：`3-32` 位，允许字母/数字/下划线
- 密码：至少 `6` 位

响应成功后会直接返回 JWT，可立即登录态使用。

### 2.3 角色权限矩阵

- `normal`：数据大屏、详情信息、扩展插件、用户中心（改自己密码）
- `admin`：普通权限 + RAG设置、日志、系统配置、管理用户（可改他人密码）

## 3. 响应与错误约定

- 成功：HTTP `200`
- 参数错误：HTTP `400`
- 未认证：HTTP `401`
- 无权限：HTTP `403`
- 资源不存在：HTTP `404`

常见错误体：

```json
{"error":"invalid_credentials"}
```

## 4. 接口清单

### 4.1 鉴权相关（v2）

- `GET /api/v2/auth/demo-accounts`
  - 说明：返回演示账号
- `POST /api/v2/auth/login`
  - body：`username`, `password`, `role?`
- `POST /api/v2/auth/register`
  - body：`username`, `password`, `display_name?`, `role=normal`
- `POST /api/v2/auth/logout`
  - 鉴权：`normal/admin`
- `GET /api/v2/auth/profile`
  - 鉴权：`normal/admin`
- `POST /api/v2/auth/change-password`
  - 鉴权：`normal/admin`
  - body：`old_password`, `new_password`

### 4.2 通用信息（v2）

- `GET /api/v2/common/system-status`
  - 鉴权：`normal/admin`
- `GET /api/v2/common/alerts/ticker?limit=3`
  - 鉴权：`normal/admin`
- `GET /api/v2/common/alerts/popup?limit=5`
  - 鉴权：`normal/admin`
- `POST /api/v2/common/alerts/{event_id}/ack`
  - 鉴权：`normal/admin`
- `GET /api/v2/common/home-background`
  - 鉴权：无
  - 说明：返回当前前端主页背景图地址，前端启动时自动读取
  - 响应示例：

```json
{
  "url": "/assets/bg-main.jpg"
}
```

### 4.2.1 扩展插件（v2）

- `POST /api/v2/plugins/phishing/check`
  - 鉴权：`normal/admin`
  - body：`url`, `token`
  - 约束：`url` 必须以 `http://` 或 `https://` 开头
  - 返回字段：`action`, `verdict`, `confidence`, `reason`, `evidence[]`

### 4.2.2 高级 RAG 工作台（v3，管理员）

- `GET /api/v3/rag/status`：云模型、数据目录、支持格式及知识库/文档/切片统计。
- `GET /api/v3/rag/knowledge-bases`：知识库列表，支持 `q` 与 `include_disabled`。
- `POST /api/v3/rag/knowledge-bases`：创建知识库。
- `GET /api/v3/rag/knowledge-bases/{kb_id}`：知识库详情。
- `PUT /api/v3/rag/knowledge-bases/{kb_id}`：更新模型、切片和召回参数。
- `POST /api/v3/rag/knowledge-bases/{kb_id}/toggle`：启用或停用。
- `POST /api/v3/rag/knowledge-bases/{kb_id}/delete`：删除知识库及其文档和向量。
- `GET /api/v3/rag/knowledge-bases/{kb_id}/documents`：文档列表。
- `POST /api/v3/rag/knowledge-bases/{kb_id}/documents/upload`：`multipart/form-data` 上传附件，字段名 `file`，最大 30MB。
- `POST /api/v3/rag/knowledge-bases/{kb_id}/documents/text`：提交 `{title, content}` 在线知识。
- `POST /api/v3/rag/documents/{document_id}/index`：为迁移文档建立向量。
- `POST /api/v3/rag/documents/{document_id}/delete`：删除文档和切片。
- `GET /api/v3/rag/knowledge-bases/{kb_id}/chunks`：切片列表，可传 `document_id`。
- `PUT /api/v3/rag/chunks/{chunk_id}`：更新 `{content, enabled}` 并重建该切片向量。
- `POST /api/v3/rag/knowledge-bases/{kb_id}/recall`：提交 `{query}`，执行 Vector + BM25 + RRF + Rerank。
- `GET /api/v3/rag/knowledge-bases/{kb_id}/recall-history`：召回测试历史。

所有 v3 接口均使用现有 JWT/Cookie 鉴权，未返回或记录 API Key。

### 4.2.3 RAG 知识库（v2，兼容）

- `GET /api/v2/rag/docs?page=1&page_size=20&q=&attack_type=`
  - 鉴权：`admin`
  - 说明：分页检索 RAG 文档
- `GET /api/v2/rag/docs/{doc_id}`
  - 鉴权：`admin`
  - 说明：读取单条 RAG 文档完整详情，前端点击列表行后调用
  - 返回字段：`doc_id`, `title`, `tags`, `attack_type`, `content`, `evidence`, `mitigation`, `severity`, `source`
- `POST /api/v2/rag/docs`
  - 鉴权：`admin`
  - body（示例）：

```json
{
  "title": "SQLi login bypass pattern",
  "attack_type": "SQLi",
  "tags": "sqli login or 1=1",
  "severity": "high",
  "content": "Rule description...",
  "evidence": "Evidence description...",
  "mitigation": "Mitigation description..."
}
```

- `PUT /api/v2/rag/docs/{doc_id}`
  - 鉴权：`admin`
  - 说明：更新指定 RAG 文档
  - body：同新增接口，`title` 与 `content` 必填
- `POST /api/v2/rag/docs/{doc_id}/update`
  - 鉴权：`admin`
  - 说明：更新指定 RAG 文档的兼容接口，前端默认使用该接口，避免部分代理/旧环境拦截 `PUT`
- `POST /api/v2/rag/docs/{doc_id}/delete`
  - 鉴权：`admin`
  - 说明：删除指定文档
- `POST /api/v2/rag/rebuild`
  - 鉴权：`admin`
  - 说明：按 `llm/rag/rag_seed.json` 重建知识库

### 4.3 普通用户大屏（v2）

- `GET /api/v2/user/dashboard/kpis`
- `GET /api/v2/user/dashboard/trend7d`
- `GET /api/v2/user/dashboard/top-attack-types`
- `GET /api/v2/user/dashboard/source-distribution`
- `GET /api/v2/user/dashboard/heatmap`
- `GET /api/v2/user/dashboard/method-share`

以上接口鉴权角色：`normal/admin`

### 4.4 详情信息（v2）

- `GET /api/v2/pro/events`
  - 鉴权：`normal/admin`
  - 查询参数：
    - `time_range`: `1h|6h|24h|7d|30d|custom`
    - `start_time`, `end_time`（`custom` 时必填，ISO 格式）
    - `risk_level`: `all|high|medium|low`
    - `attack_type`: `all|<具体类型>`
    - `target_node`: `all|<节点名>`
    - `process_status`: `all|unprocessed|processing|done|ignored`
    - `keyword`: 模糊匹配 `event_id/source_ip/target_interface`
    - `page`, `page_size`
- `GET /api/v2/pro/events/{event_id}`
  - 鉴权：`normal/admin`
- `POST /api/v2/pro/events/batch-status`
  - 鉴权：`admin`
  - body：

```json
{
  "event_ids": ["EVT20260421000001", "EVT20260421000002"],
  "process_status": "done"
}
```

- `POST /api/v2/pro/events/{event_id}/note`
  - 鉴权：`admin`
  - body：

```json
{"note":"已处置并加固WAF规则"}
```

- `POST /api/v2/pro/events/{event_id}/block-ip`
  - 鉴权：`normal/admin`
  - body（可选）：`reason`
  - 说明：按事件来源 IP 执行封禁（重复封禁会返回 `already_blocked=true`）

- `GET /api/v2/pro/model/performance`
  - 鉴权：`admin`
- `GET /api/v2/pro/nodes/{node_name}/detail`
  - 鉴权：`normal/admin`


### 4.4.1 候选事件复核（v2）

- `GET /api/v2/pro/candidates?page=1&page_size=20&q=`
  - 鉴权：`normal/admin`
  - 说明：查询 Detection V2 低/中置信候选事件，供人工复核。
  - 返回字段：`event_id`, `case_id`, `decision`, `final_score`, `risk_level`, `attack_type`, `source_ip`, `target_interface`, `created_at`

- `GET /api/v2/pro/candidates/{event_id}`
  - 鉴权：`normal/admin`
  - 说明：查看候选事件详情，返回结构兼容事件详情，并包含 `v2_detection` 证据链。

- `POST /api/v2/pro/candidates/{event_id}/promote`
  - 鉴权：`admin`
  - 说明：将候选事件提升为攻击事件，写入 `attack_events` 和兼容大屏表 `demo_attack_events`。

- `POST /api/v2/pro/candidates/{event_id}/ignore`
  - 鉴权：`admin`
  - 说明：将候选事件忽略为 `raw_only`，同时删除对应攻击事件记录，仅保留原始日志。

### 4.4.2 行为聚合与 SSH 爆破说明

- HTTP 目录扫描、路径探测、高频请求、HTTP 爆破等行为型攻击会按“来源 IP + 攻击类型 + 10 分钟时间桶”聚合。
- 聚合事件仍写入 `detection_candidates`、`attack_events` 与兼容大屏表 `demo_attack_events`，前端无需额外接口即可展示。
- SSH 爆破由 `scripts/ssh_bruteforce_monitor.py` 常驻监控 Windows 事件日志后写入同一套事件表。
- 默认阈值：同一来源 IP 在 10 分钟窗口内 SSH 登录失败达到 `5` 次，生成 `SSH爆破` 事件。
- 相关启动参数：
  - `--enable-ssh-monitor`
  - `--no-ssh-monitor`
  - `--ssh-monitor-window-minutes`
  - `--ssh-monitor-bucket-minutes`
  - `--ssh-bruteforce-threshold`
  - `--ssh-monitor-poll-seconds`

### 4.4.3 攻击者连续态势（v2）

- `GET /api/v2/situations?limit=80&status=&source_ip=&minimum_risk=0`
  - 鉴权：`normal/admin`
  - 说明：按最近动作时间倒序列出关联态势
- `GET /api/v2/situations/by-ip/{source_ip}`
  - 鉴权：`normal/admin`
  - 说明：列出指定来源 IP 的历史态势
- `GET /api/v2/situations/{situation_id}`
  - 鉴权：`normal/admin`
  - 说明：返回态势详情、动作序列、AI 报告和证据引用
- `GET /api/v2/situations/{situation_id}/graph`
  - 鉴权：`normal/admin`
  - 说明：返回适合前端绘图的 `nodes` 与 `edges`
- `GET /api/v2/situations/{situation_id}/evidence`
  - 鉴权：`normal/admin`
  - 说明：返回按时间排序的原始传感器证据摘要
- `GET /api/v2/situations/stream`
  - 鉴权：`normal/admin`
  - 说明：SSE 增量推送最近态势摘要
- `POST /api/v2/situations/{situation_id}/reanalyze`
  - 鉴权：`admin`
  - 说明：使用当前 Ollama 模型与 RAG 知识重新生成态势报告
- `POST /api/v2/situations/{situation_id}/status`
  - 鉴权：`admin`
  - body：`status=handled|ignored|open|closed|observing`

管理员配置接口 `PUT /api/v2/admin/config` 还支持：

- `situation_minimum_actions`：形成态势所需不同动作种类，范围 `3-12`
- `situation_window_minutes`：关联总窗口，范围 `1-1440`
- `situation_inactivity_minutes`：静默切段时间，范围 `1-1440`
- `scan_port_threshold`：扫描判定唯一端口数量，范围 `3-65535`
- `scan_window_seconds`：扫描聚合窗口，范围 `10-3600`

### 4.5 管理员（v2）

- `GET /api/v2/admin/summary`
- `GET /api/v2/admin/machines/ranking`
- `GET /api/v2/admin/trend7d`
- `GET /api/v2/admin/machines`
- `GET /api/v2/admin/machines/{machine_id}`
- `POST /api/v2/admin/machines/{machine_id}/restart-service`
- `GET /api/v2/admin/user-op-logs?page=1&page_size=30&username=`
- `GET /api/v2/admin/config`
- `PUT /api/v2/admin/config`
- `POST /api/v2/admin/home-background`
  - 鉴权：`admin`
  - 请求类型：`multipart/form-data`
  - 表单字段：`file`
  - 文件限制：`jpg/jpeg/png/webp`，最大 `10MB`
  - 说明：上传管理员自定义主页背景图，上传成功后自动写入系统配置并立即对前端生效
  - 响应示例：

```json
{
  "ok": true,
  "url": "/uploads/homepage_background_20260604_193629_179d6897.jpg"
}
```

- `GET /api/v2/admin/users`
- `PUT /api/v2/admin/users/{username}/password`
  - body（示例）：

```json
{
  "alert_threshold_high": "10",
  "auto_refresh_seconds": "5",
  "sound_alert_enabled": "1",
  "capture_batch_size": "4",
  "monitor_ports": "80,443,8080",
  "capture_interface": "4",
  "llm_model": "qwen2.5:3b",
  "homepage_background_url": "/assets/bg-main.jpg"
}
```

- `GET /api/v2/admin/reports/export`
  - 返回：CSV 文件流

以上接口鉴权角色：`admin`

### 4.6 兼容接口（v1）

- `GET /api/v1/screen/ping`
- `GET /api/v1/screen/attacks?limit=100&offset=0&llm_status=done`
- `GET /api/v1/screen/request-body?case_id=b.11`
- `GET /api/v1/screen/request-body?file_id=1.1.302&seq_id=1`
- `GET /api/v1/screen/response-body?case_id=b.11`
- `GET /api/v1/screen/response-body?file_id=1.1.302&seq_id=1`

查询体说明：

- `request-body` / `response-body` 必须提供：
  - `case_id`
  - 或 `file_id + seq_id`

### 4.7 高级 RAG（v3，管理员）

- `GET /api/v3/rag/status`
- `GET|POST /api/v3/rag/knowledge-bases`
- `GET|PUT /api/v3/rag/knowledge-bases/{kb_id}`
- `POST /api/v3/rag/knowledge-bases/{kb_id}/toggle`
- `POST /api/v3/rag/knowledge-bases/{kb_id}/delete`
- `GET /api/v3/rag/knowledge-bases/{kb_id}/documents`
- `POST /api/v3/rag/knowledge-bases/{kb_id}/documents/upload`
- `POST /api/v3/rag/knowledge-bases/{kb_id}/documents/text`
- `POST /api/v3/rag/documents/{document_id}/index`
- `POST /api/v3/rag/documents/{document_id}/delete`
- `GET /api/v3/rag/knowledge-bases/{kb_id}/chunks`
- `PUT /api/v3/rag/chunks/{chunk_id}`
- `POST /api/v3/rag/knowledge-bases/{kb_id}/recall`
- `GET /api/v3/rag/knowledge-bases/{kb_id}/recall-history`
- `GET|POST /api/v3/rag/knowledge-bases/{kb_id}/eval-cases`
- `PUT /api/v3/rag/knowledge-bases/{kb_id}/eval-cases/{case_id}`
- `POST /api/v3/rag/knowledge-bases/{kb_id}/eval-cases/{case_id}`，body 为 `{"action":"delete"}` 时删除
- `GET|POST /api/v3/rag/knowledge-bases/{kb_id}/eval-runs`，`POST` 执行全部已启用用例

所有 v3 接口要求管理员 JWT。上传接口使用 `multipart/form-data`，单文件最大 `30MB`；支持 `txt/md/json/jsonl/csv/pdf/docx/pptx/xlsx`。

## 5. CORS 与预检

服务已内置：

- `OPTIONS /api/v1/screen/ping`
- `OPTIONS /api/v2/<path>`

并返回跨域头：

- `Access-Control-Allow-Origin: *`
- `Access-Control-Allow-Headers: Content-Type, Authorization`
- `Access-Control-Allow-Methods: GET, POST, PUT, OPTIONS`

## 6. 变更约束

- 当前 API 契约以 `scripts/dashboard_api_server.py` 为准
- 若后端变更字段/路径，需同步更新本声明文档

