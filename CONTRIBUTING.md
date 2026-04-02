# Contributing

感谢你关注镜渊项目。

## 提交流程

1. Fork 并创建特性分支
2. 保持改动聚焦（一个 PR 解决一个问题）
3. 提交前自测：
   - `python app.py --help`
   - 关键脚本可运行
4. 提交 PR，说明：
   - 改动目的
   - 改动范围
   - 测试结果

## 代码规范

- Python 3.10+
- 新增功能优先放在 `scripts/` 或未来的 `services/`
- 根目录仅保留 `app.py` 作为统一入口
- 不提交真实敏感流量数据

## Issue 建议模板

- 问题描述
- 复现步骤
- 期望行为
- 实际行为
- 日志位置（如 `output/app_runtime/app.log`）
