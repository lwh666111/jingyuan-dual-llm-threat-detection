# Test Targets

这个目录用于启动/停止测试靶场，便于用户自行选择。

## 推荐靶场（多漏洞）

- 启动（4000端口）：`test/start_multivuln_lab_4000.ps1`
- 或双击：`test/start_multivuln_lab_4000.bat`
- 停止：`test/stop_target_labs.ps1`

默认会启动 `scripts/target_multivuln_lab.py`，覆盖 SQLi、XSS、SSRF、命令注入、路径遍历、文件上传、XXE、反序列化、开放重定向、弱鉴权等常见测试面。

## 登录靶场（兼容历史）

- 启动（3000端口）：`test/start_login_lab_3000.ps1`

## 抓包网卡建议

- 外部机器访问服务器（真实场景）：选择以太网网卡（通常是 4）
- 服务器本机访问 `127.0.0.1`（本机自测）：选择回环网卡（通常是 5）
