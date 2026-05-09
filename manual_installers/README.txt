手动依赖安装包目录（先装这些，再跑项目）

1) Npcap（必须，抓包驱动）
   文件：npcap-1.82.exe
   建议参数：默认即可，勾选 WinPcap 兼容模式

2) Wireshark（包含 tshark/dumpcap）
   文件：Wireshark_4.6.5_Machine_X64_nullsoft_zh-CN.exe
   建议安装项：确保安装 TShark 和 Npcap（若已手装 Npcap 可跳过）

3) Ollama（本地大模型服务）
   文件：OllamaSetup.exe
   安装后在命令行执行：ollama pull qwen2.5:3b

说明：
- 本目录内安装包由项目打包时一并放入，用于离线/半离线部署。
- 项目一键脚本 deploy\start_all_nodocker.ps1 会优先使用本目录安装包。
