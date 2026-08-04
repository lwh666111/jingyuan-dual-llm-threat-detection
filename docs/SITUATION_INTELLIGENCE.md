# 攻击者连续态势设计与使用说明

## 1. 目标

单条攻击告警只能说明某一次请求或连接具有风险，无法回答攻击者是否正在按“侦察、凭据攻击、漏洞利用、执行控制”的顺序持续推进。本模块在不替代 Detection V2 的前提下，将多个独立传感器产生的动作按来源、目标与时间关联，形成可以展示、解释和处置的连续攻击态势。

## 2. 形成条件

默认条件：

- 来源 IP 相同
- 目标资产相同
- 动作位于 30 分钟关联窗口内
- 相邻动作静默不超过 15 分钟
- 至少出现 3 类不同动作

端口扫描的几十或几千个 SYN 包会聚合为一个 `PORT_SCAN` 动作；同类目录扫描、路径探测和爆破请求也只累计频次，不会虚增动作种类。只有真正出现不同阶段或不同技术类型时，才会由 `observing` 升为 `open`。

## 3. 数据来源

| 传感器 | 输入 | 标准动作示例 |
|---|---|---|
| TCP SYN 扫描传感器 | tshark/Npcap | `PORT_SCAN` |
| SSH 爆破监控 | Windows Security 4625、OpenSSH 日志 | `SSH_BRUTEFORCE` |
| Detection V2 | HTTP 请求/响应、Payload、POC、行为窗口 | `SQL_INJECTION`、`XSS`、`COMMAND_INJECTION` 等 |
| 行为聚合 | 高频访问、目录探测、认证失败 | `DIRECTORY_SCAN`、`HTTP_BRUTEFORCE` 等 |

所有来源先转换为统一 `SecurityAction`，再进入关联器。统一字段包括动作 ID、来源 IP、目标资产、目标接口、动作类型、阶段、传感器、首次/末次时间、聚合次数、置信度、严重度和证据引用。

## 4. 判定与 AI 的边界

确定性关联器负责：

- 是否属于同一个来源和目标
- 是否位于关联窗口
- 是否因静默超时切段
- 动作种类是否达到阈值
- 风险分数、阶段、状态和动作顺序

Ollama + RAG 只负责解释已经形成的证据链，包括执行摘要、事件叙述、时间线、技术路径、证据强度、影响评估、失陷判断、综合结论、调查步骤、即时防护、检测优化、长期改进和证据边界。提示词明确禁止把“攻击尝试”描述为“已经入侵成功”。Ollama 不可达时会生成带 `deterministic_fallback` 标记的详细确定性报告，页面仍可正常使用。

## 5. 数据存储

MySQL 是权威主存储：

- `security_actions`：标准化动作
- `attack_situations`：态势主表与 AI 报告
- `situation_actions`：态势与动作的有序关系
- `situation_outbox`：可选图数据库同步事件

Neo4j 是可选查询镜像，保存：

```text
(SourceIP)-[:GENERATED]->(Situation)-[:TARGETED]->(Asset)
(Situation)-[:HAS_ACTION {sequence:n}]->(Action)
(Action)-[:NEXT]->(Action)
```

同步使用 Transactional Outbox。Neo4j 写入失败时只增加重试次数，不回滚 MySQL 主链路，也不会让 `app.py` 退出。

## 6. 一键启动

默认启动 MySQL 态势链路：

```powershell
python app.py
```

启用可选 Neo4j 镜像：

```powershell
python app.py --neo4j-url http://127.0.0.1:7474 --neo4j-user neo4j --neo4j-password YOUR_PASSWORD
```

Neo4j 参数为空时不会启动图同步进程。当前前端直接读取 MySQL API，因此 Neo4j 并不是部署必需项。

## 7. 管理员配置

进入“系统配置”可修改：

- 形成态势所需动作种类，默认 `3`
- 态势关联窗口，默认 `30` 分钟
- 静默切段时间，默认 `15` 分钟
- 扫描判定端口数量，默认 `10`
- 扫描聚合窗口，默认 `60` 秒

保存后，`situation_supervisor.py` 每 10 秒读取一次配置。关联参数变化时只重启关联器，扫描参数或网卡变化时只重启扫描传感器，LLM 模型变化时只重启 AI 子进程。

## 8. 页面使用

1. 登录普通用户或管理员账号。
2. 点击“态势感知展示”。
3. 从左侧选择来源 IP。
4. 中间查看动作阶段、时间间隔和聚合次数。
5. 默认“聚合视图”会合并连续同类动作，并将超长序列压缩到约 10 个可读节点；点击“证据视图”可恢复原始动作序列。
6. 右侧查看风险指数、当前阶段与会话状态。
7. 底部查看 AI 报告和可回溯证据。
8. 管理员可重新研判、标记已处置或忽略。

空页面并不表示系统故障。只有同一来源、同一目标在关联窗口内达到不同动作阈值后才会形成正式态势；不足阈值的动作仍保存在 MySQL 中供后续关联。

## 9. 验证结果

2026-08-04 本机验证：

- 48 项自动化测试全部通过
- MySQL 幂等写入与有序证据关系通过
- JWT 列表、详情、图、证据、状态与重新研判接口通过
- 端口扫描、SSH 爆破、SQL 注入跨传感器整链回放通过
- Ollama 不可达时的确定性降级报告通过
- Neo4j Transactional HTTP 请求与认证结构通过
- 1920×1080、1280×720 和 900px 窄屏布局通过，无横向溢出
- 聚合/证据双视图与详细 AI 报告向后兼容通过
- 全链路靶场 7 阶段浏览器回放通过，Fastjson 等安全模拟接口明确返回 `simulation=true`、`executed=false`

本机便携版 Wireshark 的 `tshark -D`/`dumpcap -D` 存在阻塞，因此真实抓包健康检查应视为未通过，而不是仅凭 `tshark --version` 判定正常。正式服务器部署必须在“系统配置→一键检查运行环境”中确认短时抓包探测成功。

## 10. 决赛演示数据

写入 6 组使用 RFC 保留测试地址的综合攻击链：

```powershell
python scripts\seed_situation_demo.py --mysql-port 3306
```

清除全部演示链路且不影响真实业务数据：

```powershell
python scripts\seed_situation_demo.py --mysql-port 3306 --clear
```

演示数据统一使用目标资产 `demo-finals-server` 隔离，覆盖进行中、已结束和已处置状态，并附带可解释 AI 报告与证据引用。

## 11. 全链路安全靶场

靶场按攻击推进阶段组织，而不是把所有接口堆在一个页面：

1. 信息收集：目录枚举、端口特征和 GraphQL Schema 探测。
2. 经典漏洞：SQL 注入、XSS、危险上传、命令注入、路径遍历、SSRF、XXE、SSTI、反序列化与暴力破解。
3. N-day 特征：Fastjson AutoType、Log4j Lookup、Spring 数据绑定与 Shiro 会话形态。
4. 未知威胁：深层嵌套、异常类型切换和高熵标记等新颖结构。

N-day 样本依据厂商公开公告构造，但固定使用不可执行类名、`.invalid` 域名和纯文本标记；服务端只返回检测结果，不解析外部实体、不加载类、不写文件、不发起回连。未知威胁模块用于验证“未知结构发现能力”，不等同于真实 0-day，也不包含未公开漏洞利用。
