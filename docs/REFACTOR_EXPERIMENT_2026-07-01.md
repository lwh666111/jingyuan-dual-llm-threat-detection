# 2026-07-01 服务器真实数据检测实验与重构方案

## 1. 实验背景

当前系统在服务器 `C:\Users\Administrator\Desktop\JingyuanTrafficPipeline` 上已经积累了真实抓包与检测结果。本次实验目标不是继续微调阈值，而是验证当前架构是否存在系统性误报，并评估“原始流量/候选事件/攻击事件分层 + 请求侧证据门控 + 行为检测 + POC 规则”的重构方案是否能明显改善。

## 2. 服务器数据盘点

服务器项目目录：

- `C:\Users\Administrator\Desktop\JingyuanTrafficPipeline`

数据规模：

- `input/` 抓包输入文件：401 个
- `output/` 输出文件：3248 个
- `result/` 检测事件目录：718 个
- MySQL `traffic_pipeline` 中核心表：
  - `requests`: 718 条
  - `responses`: 718 条
  - `analyses`: 718 条
  - `demo_attack_events`: 718 条

关键观察：当前数据库中没有完整的 `raw_http_logs` 原始流量表，只有已经进入 result 的事件。因此现在系统事实上是“进入 result 就进入攻击事件”，缺少原始流量和攻击事件之间的隔离层。

## 3. 当前系统主要问题

### 3.1 普通页面访问被当攻击事件

服务器真实数据中，大量普通 GET 页面访问被记录为攻击事件：

- `GET /`：98 条，其中 97 条实验判定应只保留为原始日志
- `GET /sql`：35 条，绝大多数只是打开测试页面
- `GET /xss`：23 条，均为打开测试页面
- `GET /upload`：18 条，绝大多数只是打开上传页面

典型误报：

```text
case_id=b.718
method=GET
uri=/
status_code=200
old_attack_type=XSS
old_confidence=95.0
request_body=空
```

这说明系统把“访问路径”或“响应页面中的 HTML/JS/CSS”当成了攻击证据。

### 3.2 旧模型对普通页面访问打高分

模型分数统计显示：

- `GET /`：raw_score 固定约 `0.94`，全部 label=`suspicious`
- `GET /sql`：raw_score 固定约 `0.94`，全部 label=`suspicious`
- `GET /xss`：raw_score 固定约 `0.94`，全部 label=`suspicious`
- `GET /upload`：raw_score 固定约 `0.94`，全部 label=`suspicious`

结论：问题不只是 LLM 或阈值，而是旧模型/旧特征已经把“访问漏洞演示页面”学习成攻击。竞赛版必须重训模型，并重新定义训练样本边界。

### 3.3 响应内容污染攻击判断

许多首页响应包含 HTML/CSS/JS，LLM 或导出层可能把响应里的 `<script>`、样式、页面功能说明误当成 XSS 证据。

正确逻辑应该是：

- 请求侧 payload 是主证据
- 响应侧只作为辅助确认，例如是否回显 payload、是否报错、是否泄露敏感信息
- 不能因为响应页面本身含 HTML/JS 就判定请求是 XSS

### 3.4 数据库结构不支持准确评估

当前表结构缺陷：

- `requests` 表没有 `source_ip` / `destination_ip` 原始字段
- 没有保存所有原始 HTTP 访问，只保存进入 result 的样本
- `analyses` 和 `demo_attack_events` 数量完全相同，说明分析结果和展示事件没有分层
- 部分 `attack_type` 存在乱码，说明编码链路仍需统一 UTF-8
- 没有 `model_predictions`、`poc_matches`、`behavior_windows` 等可解释中间表

这些问题会影响比赛答辩时的可信度，因为系统无法解释“为什么普通访问没有告警”以及“为什么这个攻击被告警”。

## 4. 离线实验方案

本次实验在本地对服务器导出的 718 条检测结果进行离线评估，未修改服务器运行环境。

实验方法：

1. 只使用请求侧信息作为攻击主证据：method、uri、query、headers、body。
2. 响应内容不直接参与攻击触发，只作为后续确认材料。
3. 设计实验版规则门控器，覆盖：
   - SQL 注入
   - XSS
   - 命令注入
   - 路径遍历
   - SSRF
   - XXE
   - SSTI
   - 反序列化
   - GraphQL 探测
   - 危险文件上传
4. 设计行为窗口雏形，按 IP 和时间窗口统计：
   - 登录失败次数
   - 请求次数
   - 访问路径数量
5. 最终判定分两类：
   - `attack_event`：进入攻击事件和大屏
   - `raw_only`：只保留为原始流量日志，不进入告警

## 5. 实验结果

当前系统：

- 当前攻击事件数：718

实验版门控器：

- 保留为攻击事件：479
- 压回原始日志：239
- 压制比例：33.3%
- 明显普通页面访问误报压制：至少 184 条

按原因统计：

- 请求侧明确攻击 payload：461 条
- 普通页面访问：233 条
- 请求侧无攻击证据：24 条

说明：即使不重训模型，只增加“请求侧证据门控”，也能明显降低误报。重训模型后还会进一步改善。

## 6. 对当前数据的判断

当前 718 条事件中，最可靠的攻击主要集中在：

- `/api/auth/login` 中带 SQL 注入 payload 的请求
- `/api/search?q=<script>alert(1)</script>` 这类 XSS payload
- `/api/file/read?path=../../../../etc/passwd` 这类路径遍历
- `/api/system/ping` 中含 `whoami`、`cat /etc/passwd`、`powershell` 等命令注入 payload
- `/api/xml/import` 中含 XXE 特征的请求

当前最不合理的事件主要集中在：

- `GET /`
- `GET /sql`
- `GET /xss`
- `GET /upload`
- `GET /command`
- `GET /ssrf`
- `GET /xxe`
- `GET /bruteforce`
- `GET /deserialize`
- `GET /graphql`
- `GET /ssti`

这些大多只是打开测试页面，不应进入攻击事件。

## 7. 重构方向

### 7.1 新链路

建议重构为：

```text
抓包
 -> raw_http_logs 原始流量入库
 -> 请求规范化/解码/特征提取
 -> Payload 模型
 -> 行为窗口模型
 -> POC/规则引擎
 -> 融合评分
 -> detection_candidates 候选事件
 -> attack_events 最终攻击事件
 -> LLM 解释与处置建议
 -> 前端大屏
```

关键原则：

- 所有访问都可以记录，但默认进入 `raw_http_logs`
- 只有攻击证据充分的请求才进入 `attack_events`
- LLM 只解释候选攻击，不负责从所有流量里盲判攻击

### 7.2 数据库重构

建议新增/调整表：

- `raw_http_logs`：保存所有请求响应，包含源 IP、目标 IP、端口、method、uri、headers、body、status、timestamp
- `detection_candidates`：保存模型/规则筛出的候选事件
- `attack_events`：最终进入大屏的攻击事件
- `model_predictions`：保存各模型输出分数和类别
- `poc_matches`：保存 POC/规则命中证据
- `behavior_windows`：保存 IP 行为统计窗口
- `llm_analyses`：保存 LLM 对最终事件的解释

### 7.3 模型重训方案

不建议继续沿用旧 UNSW 兼容模型作为主模型。建议拆成两个模型：

#### HTTP Payload 模型

目标：判断单条请求是否含攻击 payload。

输入：

- method
- path
- query
- headers
- body
- content-type
- status_code 作为辅助特征

输出类别：

- normal
- SQLi
- XSS
- Command Injection
- Path Traversal
- SSRF
- XXE
- SSTI
- Unsafe Upload
- RCE
- Suspicious

推荐算法：

- 第一版：字符 n-gram + LogisticRegression/LinearSVM/LightGBM
- 第二版：轻量 Char-CNN 或小型 Transformer

训练数据来源：

- HTTP CSIC 2010：Web 请求异常检测基础数据
- CSE-CIC-IDS2018：补充 Web attack、Brute-force、DoS 等行为类样本
- CICIDS2017：补充 IDS 基准流量
- OWASP CRS / Nuclei templates：生成 POC 风格合成样本
- 本项目靶场生成数据：专门生成“打开页面是正常、提交 payload 才是攻击”的对照样本

#### 行为模型

目标：识别单条请求看不出来的行为攻击。

输入窗口：

- `source_ip + target_port + endpoint + 1分钟/5分钟/10分钟`

特征：

- 请求总数
- 登录失败次数
- 401/403/404/500 比例
- 不同路径数量
- 不同账号数量
- 平均请求间隔
- User-Agent 多样性
- POST/GET 比例
- payload 命中次数

输出类别：

- normal
- brute_force
- scan
- credential_stuffing
- dos_like
- low_and_slow_probe

### 7.4 POC 识别引擎

新增 `poc_engine`，参考 Nuclei/OWASP CRS 思路，但做轻量本地规则。

规则格式建议：

```json
{
  "id": "web-sqli-login-bypass-001",
  "name": "SQL注入登录绕过",
  "severity": "high",
  "tags": ["sqli", "auth"],
  "request": {
    "path_contains": ["/login"],
    "body_regex": ["(?i)('|%27)\\s*or\\s+1\\s*=\\s*1"]
  },
  "response": {
    "status_in": [200, 500],
    "body_contains_any": ["sql", "syntax", "mysql"]
  }
}
```

POC 引擎作用：

- 给融合评分加权
- 给前端提供“命中证据”
- 给 LLM 提供上下文
- 给比赛答辩提供可解释性

### 7.5 融合评分

建议最终评分：

```text
final_score =
  payload_model_score * 0.45 +
  behavior_score * 0.30 +
  poc_rule_score * 0.20 +
  context_score * 0.05
```

进入攻击事件条件：

- `final_score >= 0.70`
- 或命中 critical/high POC
- 或行为窗口触发 brute force / scan 阈值

不进入攻击事件条件：

- 纯 GET 页面访问，无 query/body，无异常 header
- 请求侧无 payload 证据，只是响应 HTML 中出现 script/style
- 单次登录失败但没有注入 payload，也没有行为窗口异常

## 8. 分阶段落地建议

### Phase 1：快速止血

目标：立刻解决“访问路径就告警”。

- 在 `export_demo_candidates_to_result.py` 之前增加事件门控
- 只允许请求侧有攻击证据的样本进入 result
- 普通页面 GET 只进 raw log
- LLM prompt 中明确区分 request evidence 和 response evidence

### Phase 2：数据层重构

目标：建立竞赛可解释的数据底座。

- 新增 `raw_http_logs`
- 新增 `attack_events`
- 新增 `model_predictions`
- 新增 `poc_matches`
- 新增 `behavior_windows`
- 前端大屏改读 `attack_events`

### Phase 3：模型重训

目标：训练适合本项目 Web 攻击态势感知的模型。

- 下载/清洗 HTTP CSIC 2010、CSE-CIC-IDS2018、CICIDS2017
- 靶场自动生成正负样本
- 明确加入大量 normal 页面访问样本
- 训练 Payload 模型和 Behavior 模型
- 输出混淆矩阵、准确率、召回率、误报率

### Phase 4：POC 与行为检测扩充

目标：覆盖竞赛展示所需攻击面。

- SQLi、XSS、RCE、命令注入、路径遍历、文件上传、SSRF、XXE、SSTI、反序列化、弱口令爆破、目录扫描、敏感文件探测
- 每个 POC 输出证据链
- 前端详情页展示模型分数、规则命中、行为窗口、LLM 解释

## 9. 结论

本次实验说明：

1. 当前系统确实存在严重误报：普通路径访问会被记录为攻击事件。
2. 问题不是单纯阈值问题，旧模型本身会把普通页面访问打成 suspicious。
3. 仅使用请求侧证据门控，就能把 33.3% 当前事件压回原始日志。
4. 竞赛版应重构为“原始流量与攻击事件分层”的架构。
5. 模型必须重训，训练数据必须包含大量正常页面访问、正常登录、正常搜索、正常上传等负样本。
6. 爆破、扫描、撞库等行为攻击必须靠时间窗口统计，不能靠单条请求判断。
7. POC/规则引擎是必要的，可以显著提升可解释性和比赛展示效果。

建议下一步直接进入 Phase 1 + Phase 2：先把数据层和事件门控重构出来，再开始正式训练新模型。
