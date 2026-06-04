# 版本记录

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
