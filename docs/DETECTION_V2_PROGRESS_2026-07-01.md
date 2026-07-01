# Detection V2 架构落地与第二轮实验报告（2026-07-01）

## 1. 本轮完成内容

本轮已经把新架构的核心检测层做成可运行版本，并补齐到原项目主链路：抓包 input 全量入库、V2 分层检测、候选复核、攻击事件大屏同步、result/LLM 兼容链路。

新增/修改文件：

- `rules/poc_rules.json`
- `scripts/security_detection_v2.py`
- `scripts/train_payload_model_v2.py`
- `scripts/evaluate_detection_v2.py`
- `scripts/sync_detection_v2_db.py`
- `scripts/sync_raw_http_logs.py`
- `scripts/train_behavior_model_v2.py`
- `models/payload_model_v2.joblib`
- `models/behavior_model_v2.joblib`
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

- 总样本：`23271`
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

当前已实现“规则阈值 + 行为模型”的组合分析，窗口默认 5 分钟。

检测特征：

- 同 IP 请求总数
- 不同路径数量
- 登录请求数量
- 登录失败次数
- 404 数量
- User-Agent 数量
- payload/rule 命中次数
- 5xx 响应数量

当前可识别：

- 暴力破解
- 疑似暴力破解
- 扫描探测
- 疑似扫描探测
- 目录探测
- 高频请求

行为模型文件：

- `models/behavior_model_v2.joblib`

行为模型训练脚本：

```powershell
python scripts/train_behavior_model_v2.py
```

行为模型训练集采用合成窗口特征，覆盖 normal、bruteforce、scan、high_frequency、dir_probe、payload_burst。训练报告：

- Accuracy：`0.9952`
- Macro F1：`0.9952`

为避免行为模型过度积极，当前加入了上下文门控：窗口内请求量和异常证据不足时，行为模型只记录特征，不参与提升告警。

### 5.1 行为型攻击聚合上报

目录扫描、路径探测、高频请求和爆破登录通常不是单包攻击，而是同一来源 IP 在短时间内产生大量相似异常行为。如果逐条请求上报，几万条字典扫描会把大屏、详情列表和 LLM 队列全部刷爆。

当前处理策略：

- 单条 HTTP 请求仍会进入 `raw_http_logs`，保证原始证据不丢失。
- 行为窗口达到攻击事件条件后，不再按每个请求生成独立告警。
- 聚合键：`来源 IP + 攻击类型 + 10 分钟时间桶`。
- 聚合后的事件 ID 以 `AGG` 开头，重复命中时更新同一条 `detection_candidates`、`attack_events` 和 `demo_attack_events`。
- 聚合证据中记录窗口范围、请求总数、不同路径数、404 次数、登录失败次数和代表性证据。

验证结果：

- 模拟 60 条目录扫描请求，其中 48 条达到 `attack_event` 条件。
- 聚合后最终只生成 1 个上报事件 ID。
- 这解决了“大字典扫描产生大量疑似流量”的展示与处置问题。

### 5.2 SSH 爆破监控

SSH 爆破不是 HTTP 请求，无法通过 tshark HTTP 抓包链路识别。因此新增独立监控进程：

- 脚本：`scripts/ssh_bruteforce_monitor.py`
- 默认随 `app.py` 启动。
- 读取 Windows `Security` 日志中的 `4625` 登录失败事件。
- 同时读取 `OpenSSH/Operational` 日志中的 OpenSSH 认证失败事件。
- 按来源 IP 与 10 分钟窗口聚合，默认失败次数达到 5 次生成 `SSH爆破`。
- 事件写入同一套 MySQL 表：`detection_candidates`、`attack_events`、`behavior_windows`、`demo_attack_events`。

启动参数：

```powershell
python app.py --mysql-port 3307
python app.py --mysql-port 3307 --no-ssh-monitor
python app.py --mysql-port 3307 --ssh-bruteforce-threshold 10
```

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
- payload_score >= 0.94：进入 attack_event
- payload_score >= 0.90：进入 candidate，等待复核或结合 POC/行为证据再升级
- 普通 GET 页面访问且无 query/body/POC：进入 raw_only
- 仅“认证接口 + 较高 Payload 模型分”不再直接进入 attack_event，避免正常账号密码登录误报。

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

- `attack_event`: 476
- `raw_only`: 242
- 总数：718

也就是说：

```text
旧系统中的 242 条事件会被 V2 压回原始日志，不再进入告警/大屏。
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

### 8.4 input 原始日志全量入库与大屏同步桥

新增同步脚本：

```powershell
python scripts/sync_raw_http_logs.py --input-dir input --mysql-host 127.0.0.1 --mysql-port 3306 --mysql-user root --mysql-password 123456 --mysql-database traffic_pipeline
```

`result_db_daemon.py` 当前会同时监听：

- `result/b.n`
- `input/1.1.n.txt`

这样所有 HTTP 请求/响应都会先进入 `raw_http_logs`。随后 Detection V2 会判定是否写入：

- `detection_candidates`
- `attack_events`
- `demo_attack_events`

其中 `demo_attack_events` 是旧大屏和详情页正在读取的兼容表。V2 的 `attack_event` 会同步写入该表，保证大屏实时刷新；`raw_only` 会删除对应告警，只保留原始日志。

新增候选复核接口：

- `GET /api/v2/pro/candidates`
- `GET /api/v2/pro/candidates/{event_id}`
- `POST /api/v2/pro/candidates/{event_id}/promote`
- `POST /api/v2/pro/candidates/{event_id}/ignore`

前端“详情信息”页面已新增“候选事件复核队列”。管理员可以查看候选事件、提升为攻击事件或忽略。

### 8.5 详情接口与前端证据链

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

### 8.6 风险级别兼容

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
- 行为窗口已加入第一版机器学习模型，后续可继续用真实灰度数据训练 LightGBM/XGBoost。
- 前端列表仍以旧的 `demo_attack_events` 为主表，保证兼容现有大屏；V2 raw 同步已自动把 `attack_event` 写入该表。
- `raw_http_logs` 已接入抓包 input 全量入库。正常访问不再进入大屏告警。

## 11. 本地联调记录

本地已完成以下验证：

- Python 编译检查：`app.py`、v2 训练/评估/导出/同步/API 脚本均通过。
- 前端 JS 语法检查：`node --check frontend_dashboard/public/app.js` 通过。
- 离线评估：
  - Adversarial 小样本：Accuracy `1.0000`，Macro F1 `1.0000`
  - 服务器真实可标注样本：Accuracy `0.9982`，Macro F1 `0.9868`
- 临时 MySQL 冒烟：
  - `raw_http_logs` 全量保留 3 条测试 HTTP。
  - SQL 注入、XSS 两条进入 `attack_events` 与 `demo_attack_events`。
  - 正常登录不进入候选/攻击事件。
  - 候选事件列表、详情、提升、忽略接口均通过。
- 浏览器联调：
  - 管理员登录成功。
  - 详情信息页可显示 v2 证据链、攻击列表和候选事件复核队列。
  - `critical` 显示为红色严重级别。
  - 中文证据链显示正常，无乱码。

## 12. 下一步建议

1. 扩展 POC 规则：SQLi time-based/error-based、DOM XSS、文件上传后门、常见 CVE 指纹。
2. 增加人工复核反馈闭环：前端把误报/漏报写回训练样本池。
3. 引入 HTTP CSIC 2010、CSE-CIC-IDS2018 等公开数据做更大规模外部评估。
4. 用靶场自动发 1000 正常 + 1000 攻击流量，持续验证真实链路误报/漏报。
5. 将候选复核操作沉淀为训练样本池，实现“忽略/提升 -> 后续训练”的闭环。



