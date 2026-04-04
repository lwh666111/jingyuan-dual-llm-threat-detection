# LLM 工作目录

- `prompts/system_prompt.txt`：守护脚本读取的系统提示词
- `schemas/analysis.schema.json`：结构化输出 JSON Schema
- `outputs/`：可选聚合输出目录（当前每个 case 输出在 `result/b.n/analysis.json`）

推荐先用：

```powershell
python scripts\llm_analyzer_daemon.py --once --model qwen3:8b --num-gpu 0
```

说明：
- `--num-gpu 0` 强制 CPU 推理，更稳定（避免 4060 显存布局错误）
- 后续可尝试 `--num-gpu 20`（自动/GPU）提升速度
