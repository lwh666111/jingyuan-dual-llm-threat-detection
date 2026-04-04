# JingYuan: Dual-LLM Threat Detection

JingYuan is a dual-LLM-driven network attack detection and situation awareness system.

Current stage focuses on an end-to-end automated pipeline:

- Capture HTTP traffic from a selected network interface and TCP port
- Build canonical batch files (`input/1.1.n.txt`) from complete request/response pairs
- Auto-detect newly arrived batches
- Run compatibility inference pipeline
- Export suspicious cases into `result/b.n` for downstream LLM analysis and frontend visualization

## Repository

Recommended repo name: `jingyuan-dual-llm-threat-detection`

## Key Features

- Single entry point: `app.py`
- Configurable port monitoring (`80`, `3000`, `10086`, etc.)
- Batch by complete HTTP request/response records (not raw packet slicing)
- Automatic detection daemon for new input files
- Structured case export for downstream analysis

## Project Layout

```text
.
├─ app.py
├─ scripts/
├─ docs/
├─ input/
├─ output/
├─ result/
├─ requirements.txt
├─ CONTRIBUTING.md
├─ SECURITY.md
├─ LICENSE
└─ README.md
```

## Quick Start

1. Install dependencies:

```powershell
python -m pip install -r requirements.txt
```

2. Start the full workflow (capture + detect + LLM):

```powershell
python app.py --port 80 --capture-batch-size 4
```

3. Show all options:

```powershell
python app.py --help
```

## Common Commands

Listen on port 3000:

```powershell
python app.py --port 3000 --capture-batch-size 1
```

Capture only:

```powershell
python app.py --only-capture --port 80
```

Detect only:

```powershell
python app.py --only-detect --no-skip-existing-at-start
```

Detect only (without LLM):

```powershell
python app.py --only-detect --no-llm
```

Run LLM analysis daemon (file-output mode, no DB):

```powershell
python scripts\llm_analyzer_daemon.py --once --model qwen3:8b --num-gpu 0
python scripts\llm_analyzer_daemon.py --model qwen3:8b --num-gpu 0
```

Disable LLM in unified app entry:

```powershell
python app.py --no-llm
```

## Workflow

1. `scripts/capture_http_request_batches.py`
2. `input/1.1.n.txt`
3. `scripts/run_demo_daemon.py`
4. `scripts/demo_workflow.py`
   - `extract_old_model_features_from_txt.py`
   - `run_old_model_direct.py`
   - `rerank_model_result.py`
   - `build_demo_candidates.py`
   - `export_demo_candidates_to_result.py`
5. `result/b.n`
6. `scripts/llm_analyzer_daemon.py` reads `result/b.n` and writes:
   - `result/b.n/analysis.json`
   - `result/b.n/analysis_raw.txt`

## Logs and State

- App runtime logs: `output/app_runtime/`
- Daemon state: `output/demo_daemon_state.json`
- Per-run logs: `output/daemon_runs/`
- LLM runtime logs: `output/app_runtime/llm_stdout.log`, `output/app_runtime/llm_stderr.log`

## LLM Directory

- `llm/prompts/system_prompt.txt`: system prompt
- `llm/schemas/analysis.schema.json`: output schema
- `llm/README.md`: LLM usage notes

## Roadmap

- [x] Automated capture and batch generation
- [x] Automated detection daemon
- [x] Structured suspicious case export
- [ ] Dual-LLM inference layer for threat explanation
- [ ] Structured outputs: source IP, target IP, attack type, path, time, target
- [ ] Frontend situation awareness dashboards
- [ ] Database persistence and querying

## Responsible Use

Use only in authorized environments for defense, testing, and research.

## Docs

- Main guide: `docs/PROJECT_GUIDE.md`
- Contribution guide: `CONTRIBUTING.md`
- Security policy: `SECURITY.md`

## License

MIT
