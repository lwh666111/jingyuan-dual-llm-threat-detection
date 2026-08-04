# 版本记录

## v2026.08.04

- 日期：2026-08-04
- 分支：`main`
- AI 研判：态势报告扩展为执行摘要、事件叙述、时间线、技术路径、证据强度、影响、失陷判断、综合结论、调查步骤、即时防护、检测优化、长期改进和证据边界；Ollama 不可用时的确定性降级报告同步扩充。
- 链路展示：新增“聚合视图 / 证据视图”。默认合并连续同类动作，并把超长动作序列压缩至约 10 个可读节点，原始证据仍完整保留。
- 验证靶场：重构为信息收集、经典漏洞、N-day 特征模拟、未知威胁模拟四阶段工作台，新增 7 阶段一键回放。N-day 样本参考 Fastjson、Log4j、Spring、Shiro 官方公告，全部为不可执行检测标记。
- 前端：依据已安装的 `design-taste-frontend` Skill 完成证据优先审美审计，统一为低装饰、高密度的企业安全工作台，并保留原有信息架构与全部权限入口。
- 验证：48 项自动化测试全部通过；本机浏览器完成管理员登录、态势聚合视图、证据追溯、全链路回放和 Fastjson 安全模拟接口验收。

## v2026.08.03

- 日期：2026-08-03
- 分支：`main`
- 说明：新增跨传感器“攻击者连续态势”能力，将端口扫描、SSH 爆破、HTTP 漏洞利用等动作按来源 IP、目标资产和时间窗关联为可解释攻击链。
- 后端：新增标准化动作模型、态势关联器、TCP SYN 扫描传感器、MySQL 态势四表、AI/RAG 态势研判、守护进程自愈和可选 Neo4j Outbox 图镜像。
- 前端：新增“态势感知展示”，支持攻击者筛选、动画链路、风险概览、证据回溯、AI 报告、重新研判和处置状态；完成 1920×1080、1280×720 与 900px 窄屏验收。
- 配置：管理员可动态调整形成态势所需动作种类、关联窗口、静默切段、扫描端口阈值与扫描聚合窗口。
- 验证：41 项自动化测试通过，覆盖关联算法、增量入库、POC 规则完整性、中文 AI 报告与成功断言约束、滚动窗口扫描聚合、跨分钟边界、演示数据幂等性、MySQL、JWT API、AI 降级、Neo4j 请求、动态配置和扫描→SSH→SQL→AI→数据库→API 整链回放。
- 说明：本机便携版 Wireshark 存在网卡枚举阻塞，系统会在运行环境检查中明确报告；正式部署仍需用目标机器真实业务网卡完成短时抓包探测。

## v2026.07.01

- 日期：2026-07-01
- 分支：`main`
- 说明：Detection V2 重构验证版。完成 raw 全量入库、候选事件复核队列、行为窗口模型、大屏同步桥和正常登录误报修复。
- 本次补充：RAG 知识库支持点击查看详情与在线编辑保存；HTTP 目录扫描、路径探测、高频请求、HTTP 爆破改为窗口聚合上报，避免大字典扫描刷屏；新增 SSH 爆破监控进程，读取 Windows 失败登录事件并生成 `SSH爆破` 告警。
- 验证：Adversarial Accuracy/Macro F1 `1.0000/1.0000`；服务器真实可标注样本 Accuracy/Macro F1 `0.9982/0.9868`；本地 MySQL/API/前端浏览器烟测通过。
- 新增验证：60 条目录扫描请求聚合为 1 个上报 ID；SSH 日志来源 IP 解析 smoke test 通过；服务器同步后 `py_compile` 通过。
- 安装包：`dist/JingyuanTrafficPipeline_Setup_ManualDeps.exe`
- 安装包大小/SHA256：以当前 `dist` 目录实际文件为准，可执行：

```powershell
Get-FileHash .\dist\JingyuanTrafficPipeline_Setup_ManualDeps.exe -Algorithm SHA256
(Get-Item .\dist\JingyuanTrafficPipeline_Setup_ManualDeps.exe).Length
```
## v2026.06.04

- 日期：2026-06-04
- 分支：`main`
- 说明：服务器验证版发布。更新 Web 攻击检测模型，降低普通登录误报，增强 SQL 注入、XSS、命令注入、路径遍历、危险文件上传等典型漏洞流量识别；新增异常流量机械音提醒；管理员系统配置新增主页背景图上传；安装包版本同步至 `2026.06.04`。
- 服务器验证：已在 Windows Server 环境完成 MySQL、tshark/Npcap、Ollama、抓包、检测、LLM、入库、API、大屏链路启动验证。
- 安装包：`dist/JingyuanTrafficPipeline_Setup_ManualDeps.exe`
- 安装包大小/SHA256：以当前 `dist` 目录实际文件为准，可执行：

```powershell
Get-FileHash .\dist\JingyuanTrafficPipeline_Setup_ManualDeps.exe -Algorithm SHA256
(Get-Item .\dist\JingyuanTrafficPipeline_Setup_ManualDeps.exe).Length
```

## v2026.05.09

- 日期：2026-05-09
- 分支：`main`
- 说明：系统配置增强版恢复，钓鱼插件 token 错误提示增强，No-Docker 一键部署脚本增强（本地安装包优先、MySQL 自动检测）。
- 安装包：`dist/JingyuanTrafficPipeline_Setup_ManualDeps.exe`
- 安装包大小：`113,050,820` 字节
- 安装包 SHA256：`16BB36F2E093EF941A78ACB6CA59D84F2AA9468644F9D68C852578373B10D34D`

## v2026.05.04

- 日期：2026-05-04
- 说明：3000 端口检测链路可靠性修复（模型文件补齐、BOM 兼容、抓包配置增强），新增 `test/` 靶场脚本目录。


