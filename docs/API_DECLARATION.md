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

### 2.1 登录

`POST /api/v2/auth/login`

请求体：

```json
{
  "username": "admin",
  "password": "admin",
  "role": "normal"
}
```

`role` 可选值：`normal | pro | admin`。
建议传 `role`，避免同用户名场景下角色歧义。

响应示例：

```json
{
  "token": "xxx",
  "expires_in": 43200,
  "role": "normal",
  "display_name": "普通用户"
}
```

### 2.2 角色权限矩阵

- `normal`：普通大屏与公共信息
- `pro`：普通权限 + 专业查询与模型性能
- `admin`：全量权限（机器管理、配置、报表、日志）

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
  - 说明：返回演示账号（当前均为 `admin/admin`）
- `POST /api/v2/auth/login`
  - body：`username`, `password`, `role?`
- `POST /api/v2/auth/logout`
  - 鉴权：`normal/pro/admin`
- `GET /api/v2/auth/profile`
  - 鉴权：`normal/pro/admin`

### 4.2 通用信息（v2）

- `GET /api/v2/common/system-status`
  - 鉴权：`normal/pro/admin`
- `GET /api/v2/common/alerts/ticker?limit=3`
  - 鉴权：`normal/pro/admin`
- `GET /api/v2/common/alerts/popup?limit=5`
  - 鉴权：`normal/pro/admin`
- `POST /api/v2/common/alerts/{event_id}/ack`
  - 鉴权：`normal/pro/admin`

### 4.3 普通用户大屏（v2）

- `GET /api/v2/user/dashboard/kpis`
- `GET /api/v2/user/dashboard/trend7d`
- `GET /api/v2/user/dashboard/top-attack-types`
- `GET /api/v2/user/dashboard/source-distribution`
- `GET /api/v2/user/dashboard/heatmap`
- `GET /api/v2/user/dashboard/method-share`

以上接口鉴权角色：`normal/pro/admin`

### 4.4 专业用户（v2）

- `GET /api/v2/pro/events`
  - 鉴权：`pro/admin`
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
  - 鉴权：`pro/admin`
- `POST /api/v2/pro/events/batch-status`
  - 鉴权：`pro/admin`
  - body：

```json
{
  "event_ids": ["EVT20260421000001", "EVT20260421000002"],
  "process_status": "done"
}
```

- `POST /api/v2/pro/events/{event_id}/note`
  - 鉴权：`pro/admin`
  - body：

```json
{"note":"已处置并加固WAF规则"}
```

- `GET /api/v2/pro/model/performance`
  - 鉴权：`pro/admin`
- `GET /api/v2/pro/nodes/{node_name}/detail`
  - 鉴权：`pro/admin`

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
  - body（示例）：

```json
{
  "alert_threshold_high": "10",
  "auto_refresh_seconds": "5",
  "sound_alert_enabled": "1"
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
