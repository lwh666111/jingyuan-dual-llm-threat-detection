# Test Targets

这个目录用于启动/停止测试靶场，便于用户自行选择。

## 推荐靶场（多漏洞）

- 启动（4000端口）：`test/start_multivuln_lab_4000.ps1`
- 或双击：`test/start_multivuln_lab_4000.bat`
- 停止：`test/stop_target_labs.ps1`

默认会启动 `scripts/target_multivuln_lab.py`，覆盖 SQLi、XSS、SSRF、命令注入、路径遍历、文件上传、XXE、反序列化、开放重定向、弱鉴权等常见测试面。

启动后可打开首页：

- 本机访问：`http://127.0.0.1:4000/`
- 服务器桌面快捷方式：`C:\Users\Administrator\Desktop\TrafficTestLabs\open_4000_lab_home.bat`

多页面入口：

- `/sql`：SQL 注入测试
- `/xss`：XSS 测试
- `/upload`：文件上传测试
- `/command`：命令注入测试
- `/traversal`：路径遍历测试
- `/ssrf`：SSRF 测试
- `/xxe`：XXE 测试
- `/ssti`：模板注入测试
- `/deserialize`：反序列化测试
- `/graphql`：GraphQL 测试
- `/bruteforce`：暴力破解测试

## 登录靶场（兼容历史）

- 启动（3000端口）：`test/start_login_lab_3000.ps1`

## 抓包网卡建议

- 外部机器访问服务器（真实场景）：选择以太网网卡（通常是 4）
- 服务器本机访问 `127.0.0.1`（本机自测）：选择回环网卡（通常是 5）
