# Detection V2 架构落地与第一轮实验报告（2026-07-01）

## 1. 本轮完成内容

本轮已经把新架构的核心检测层做成可运行版本，并接入原项目主链路的 result 导出口。

新增/修改文件：

- `rules/poc_rules.json`
- `scripts/security_detection_v2.py`
- `scripts/train_payload_model_v2.py`
- `scripts/evaluate_detection_v2.py`
- `scripts/sync_detection_v2_db.py`
- `models/payload_model_v2.joblib`
- `scripts/export_demo_candidates_to_result.py`
- `scripts/demo_workflow.py`
- `scripts/run_demo_daemon.py`
- `scripts/result_db_daemon.py`
- `app.py`

## 2. 新检测链路

当前 Detection V2 核心链路：

```text
候选请求
 -> HTTP 规范化/解码
 -> Payload 模型预测
 -> POC 规则引擎匹配
 -> 行为窗口分析
 -> 融合评分
 -> raw_only / candidate / attack_event
```

其中：

- `raw_only`：只保留为原始日志，不进入 result，不进入大屏告警。
- `candidate`：疑似事件，可进入候选池等待复核。
- `attack_event`：高置信攻击事件，进入 result、LLM、DB、大屏链路。

## 3. Payload 模型

模型文件：

- `models/payload_model_v2.joblib`

模型方案：

```text
TF-IDF 字符 n-gram (3,5) + LogisticRegression(class_weight=balanced)
```

当前支持类别：

- normal
- SQL注入
- XSS
- 命令注入
- 路径遍历
- SSRF
- XXE
- SSTI
- 危险文件上传
- 反序列化
- GraphQL探测

训练样本来源：

- 靶场接口模板合成的正常请求
- 靶场接口模板合成的攻击请求
- PayloadsAllTheThings/OWASP CRS 风格 payload 模板
- 服务器真实误报 hard negative
- 服务器真实攻击 hard positive

训练样本数量：

- 总样本：`24671`
- 服务器 hard samples：`557`

训练集切分评估：

- Accuracy：`1.0000`
- Macro F1：`1.0000`

说明：训练集切分结果接近满分，说明样本边界清晰，但不能单独作为最终效果依据；因此额外做了 adversarial 和服务器真实数据评估。

## 4. POC 规则引擎

规则文件：

- `rules/poc_rules.json`

当前规则覆盖：

- SQL注入登录绕过
- 通用 SQL 注入
- 反射型 XSS
- 命令注入
- 路径遍历/敏感文件读取
- SSRF 内网访问
- XXE 外部实体
- SSTI 服务端模板注入
- 危险文件上传
- 反序列化
- GraphQL Introspection 探测

POC 规则作用：

- 给融合评分加权
- 输出证据链
- 修正 Payload 模型主类型
- 给 LLM 和前端详情页提供可解释依据

## 5. 行为窗口分析

当前已实现第一版规则阈值行为分析，窗口默认 5 分钟。

检测特征：

- 同 IP 请求总数
- 不同路径数量
- 登录请求数量
- 登录失败次数
- 404 数量
- User-Agent 数量
- payload/rule 命中次数

当前可识别：

- 暴力破解
- 疑似暴力破解
- 扫描探测
- 疑似扫描探测
- 目录探测
- 高频请求

## 6. 融合评分

融合评分来源：

```text
final_score =
  payload_score * 0.45 +
  behavior_score * 0.30 +
  poc_score * 0.20 +
  context_score * 0.05
```

强规则：

- 命中 high/critical POC：进入 attack_event
- 行为窗口达到高危阈值：进入 attack_event
- payload_score >= 0.90：进入 attack_event
- 普通 GET 页面访问且无 query/body/POC：进入 raw_only

## 7. 评估结果

### 7.1 Adversarial 小样本测试

测试包含：

- 正常搜索中出现 `union`、`script`、`select` 等非攻击语义
- 正常打开 `/sql`、`/xss`、`/upload`
- 正常登录失败
- 编码 SQLi
- 编码 XSS
- 命令注入
- 双重编码路径遍历
- SSRF
- XXE
- SSTI
- 危险上传 `.phtml`
- 反序列化
- GraphQL 探测

结果：

- Accuracy：`1.0000`
- Macro F1：`1.0000`
- 普通样本：全部 `raw_only`
- 攻击样本：全部 `attack_event`

### 7.2 服务器真实可标注样本评估

服务器真实样本来自：

- `output/server_all_joined_rows.json`

可标注样本：`561`

结果：

- Accuracy：`0.9982`
- Macro F1：`0.9868`
- normal 召回：`1.0000`
- SQL注入 F1：`1.0000`
- XSS F1：`0.9231`
- XXE F1：`1.0000`
- 命令注入 F1：`1.0000`
- 路径遍历 F1：`1.0000`

### 7.3 服务器全量 718 条旧事件重判

Detection V2 决策：

- `attack_event`: 480
- `raw_only`: 238
- 总数：718

也就是说：

```text
旧系统中的 238 条事件会被 V2 压回原始日志，不再进入告警/大屏。
```

这直接解决了“访问某个路径就一定记录成攻击事件”的核心问题。

## 8. 集成方式

### 8.1 result 导出口接入

`export_demo_candidates_to_result.py` 新增：

```powershell
--enable-v2-gate
```

启用后：

- `raw_only` 不导出到 `result/b.n`
- `candidate` / `attack_event` 会导出，并带上 v2 字段
- `attack_type` 优先使用融合后的主类型

### 8.2 app.py 默认启用

`app.py` 当前默认启用 v2 gate。

回退旧逻辑：

```powershell
python app.py --disable-v2-gate
```

### 8.3 DB 分层表

新增同步脚本：

```powershell
python scripts/sync_detection_v2_db.py --result-dir result --mysql-host 127.0.0.1 --mysql-port 3307 --mysql-user root --mysql-password 123456 --mysql-database traffic_pipeline
```

`result_db_daemon.py` 已在 MySQL 模式下自动同步以下 v2 表：

- `raw_http_logs`
- `detection_candidates`
- `attack_events`
- `model_predictions`
- `poc_matches`
- `behavior_windows`

### 8.4 详情接口与前端证据链

`dashboard_api_server.py` 的事件详情接口已经兼容读取 v2 分层表：

```http
GET /api/v2/pro/events/{event_id}
```

返回 JSON 在旧字段基础上新增 `v2_detection`：

```json
{
  "v2_detection": {
    "case_id": "b.1",
    "event_id": "EVT1",
    "decision": "attack_event",
    "final_score": 0.96,
    "risk_level": "critical",
    "attack_type": "SQL注入",
    "source_ip": "10.23.45.67",
    "target_interface": "/login",
    "evidence": [],
    "candidate": {},
    "attack_event": {},
    "raw_http": {},
    "model_predictions": [],
    "poc_matches": [],
    "behavior_windows": []
  }
}
```

兼容策略：

- 老事件表使用 `case_id` 作为事件 ID，例如 `b.135`。
- v2 分层表使用 `EVT135` 作为 `event_id`，同时保留 `case_id=b.135`。
- 接口会同时尝试 `b.n`、`EVTn` 和 `case_id` 查询，避免同一事件跨表查不到。
- 如果 v2 表不存在或该事件尚未同步，接口仍返回旧详情，不影响旧版本页面。

前端 `frontend_dashboard/public/app.js` 已在事件详情页新增“新架构证据链”面板，展示：

- 融合判定：原始日志 / 候选事件 / 攻击事件
- 融合评分
- Payload 模型预测与置信度
- POC 规则命中、严重等级、证据片段
- 行为窗口证据
- 原始请求/响应折叠详情

### 8.5 风险级别兼容

Detection V2 新增 `critical` 风险级别。前后端已做兼容：

- 前端风险筛选新增“严重”。
- `critical` 和 `high` 都使用红色高危 badge。
- 后端系统状态、高危告警、机器告警统计、报告导出均将 `critical/high` 共同计入高风险告警。

## 9. 集成烟测

构造 7 条候选：

1. `GET /xss` 普通页面访问
2. 普通登录失败
3. SQL 注入登录绕过
4. XSS 搜索参数
5. 命令注入 ping 参数
6. 危险文件上传
7. 路径遍历

结果：

- v2 raw-only filtered：2
- v2 attack-event exported：5
- 导出的攻击类型：
  - SQL注入
  - XSS
  - 命令注入
  - 危险文件上传
  - 路径遍历

说明：普通页面和普通登录失败不会再进入 result，攻击 payload 正常进入原链路。

## 10. 当前限制

- Payload 模型当前主要使用合成数据 + 服务器 hard samples，后续应继续接入 HTTP CSIC 2010、CSE-CIC-IDS2018 等公开数据做更大规模评估。
- 行为窗口第一版是规则阈值，后续可以训练 LightGBM/XGBoost。
- 前端列表仍以旧的 `demo_attack_events` 为主表，保证兼容现有大屏；详情页已通过 `v2_detection` 读取分层证据链。
- `raw_http_logs` 当前主要同步 result 内的样本。下一阶段应把抓包后的所有原始 HTTP 请求先入 `raw_http_logs`，再进入检测。

## 11. 本地联调记录

本地已完成以下验证：

- Python 编译检查：`app.py`、v2 训练/评估/导出/同步/API 脚本均通过。
- 前端 JS 语法检查：`node --check frontend_dashboard/public/app.js` 通过。
- 离线评估：
  - Adversarial 小样本：Accuracy `1.0000`，Macro F1 `1.0000`
  - 服务器真实可标注样本：Accuracy `0.9982`，Macro F1 `0.9868`
- 临时 MySQL 冒烟：
  - v2 分层表可创建。
  - `b.1` 和 `EVT1` 均可查到同一事件详情。
  - POC、模型预测、原始请求可正常返回。
- 浏览器联调：
  - 管理员登录成功。
  - 详情信息页可显示 v2 证据链。
  - `critical` 显示为红色严重级别。
  - 中文证据链显示正常，无乱码。

## 12. 下一步建议

1. 把抓包解析结果直接写入 `raw_http_logs`，实现真正“所有访问先入原始日志”。
2. 下载/整理 HTTP CSIC 2010、CSE-CIC-IDS2018，补充外部评估报告。
3. 用靶场自动发 1000 正常 + 1000 攻击流量，验证真实链路误报/漏报。
4. 在服务器上灰度部署 v2 gate，并观察大屏是否不再展示普通路径访问。
5. 将 `detection_candidates` 做成前端复核队列：低置信候选不直接告警，但可供专业用户审核。
