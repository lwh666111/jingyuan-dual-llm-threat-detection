# LLM 工作目录

- `prompts/system_prompt.txt`：守护脚本读取的系统提示词
- `schemas/analysis.schema.json`：结构化输出 JSON Schema
- `outputs/`：可选聚合输出目录（当前每个 case 输出在 `result/b.n/analysis.json`）
- `rag/rag_seed.json`：RAG 知识库种子数据
- `rag/rag_knowledge.db`：RAG SQLite FTS5 检索库

构建 RAG 知识库：

```powershell
python scripts\build_rag_db.py --seed-file llm/rag/rag_seed.json --db-path llm/rag/rag_knowledge.db
```

推荐先用：

```powershell
python scripts\llm_analyzer_daemon.py --once --model <your_ollama_model> --num-gpu 0
```

启用 RAG：

```powershell
python scripts\llm_analyzer_daemon.py --model <your_ollama_model> --rag-enable --rag-db-path llm/rag/rag_knowledge.db --rag-top-k 3
```

说明：
- `--num-gpu 0` 强制 CPU 推理，更稳定（避免 4060 显存布局错误）
- 后续可尝试 `--num-gpu 20`（自动/GPU）提升速度
- 若传入模型不存在，守护会自动回退到本机 `ollama /api/tags` 返回的第一个可用模型
- `--rag-enable` 开启检索增强，`--rag-top-k` 控制召回条数
- 若 RAG db 不存在，默认会根据 seed 自动构建（可用 `--no-rag-auto-build` 关闭）
