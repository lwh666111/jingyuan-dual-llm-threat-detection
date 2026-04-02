# 项目使用指南（镜渊）

## 1. 系统定位

镜渊（JingYuan）是面向网络攻击检测与态势感知的工程系统。

当前版本侧重于：

- 自动抓包
- 自动检测
- 候选告警导出

下一版本将接入双层大模型进行高质量语义研判与情报输出。

---

## 2. 工作流架构

```text
网络流量
  -> capture_http_request_batches.py
  -> input/1.1.n.txt
  -> run_demo_daemon.py
  -> demo_workflow.py
      -> extract_old_model_features_from_txt.py
      -> run_old_model_direct.py
      -> rerank_model_result.py
      -> build_demo_candidates.py
      -> export_demo_candidates_to_result.py
  -> result/b.n/
```

---

## 3. 脚本职责说明

### app.py（统一入口）

- 启动抓包子流程
- 启动检测守护子流程
- 管理子进程生命周期
- 输出统一运行日志

### scripts/capture_http_request_batches.py

- 监听指定端口
- 提取完整 HTTP 请求/响应对
- 按 batch 输出 `input/1.1.n.txt`

### scripts/run_demo_daemon.py

- 轮询监听 `input/`
- 发现新文件后调用 `demo_workflow.py`
- 记录成功/失败状态，避免重复处理

### scripts/demo_workflow.py

单文件检测总控，串联调用后续脚本：

1. extract_old_model_features_from_txt.py
2. run_old_model_direct.py
3. rerank_model_result.py
4. build_demo_candidates.py
5. export_demo_candidates_to_result.py

### scripts/extract_old_model_features_from_txt.py

- 支持 canonical txt 与 verbose txt
- 提取旧模型兼容输入
- 输出 raw_index 供回查

### scripts/run_old_model_direct.py

- 加载 preprocessor + 旧模型
- 推理得到 score / label

### scripts/rerank_model_result.py

- 对结果排序与标准化分数

### scripts/build_demo_candidates.py

- 生成候选请求集合

### scripts/export_demo_candidates_to_result.py

- 导出候选到 `result/b.n`
- 维护 `manifest.jsonl`

---

## 4. 运行方式

### 一键全流程

```powershell
python app.py --port 80 --capture-batch-size 4
```

### 查看所有参数

```powershell
python app.py --help
```

---

## 5. 常见参数建议

- 靶场 HTTP：`--port 3000 --capture-batch-size 1`
- 高频业务：`--capture-batch-size 10~20`
- 检测容忍度：`--export-min-score 0.3`（可调）
- 启动时仅处理新文件：默认 `--skip-existing-at-start`

---

## 6. 输出与回查

### 输入文件

- `input/1.1.n.txt`

### 检测输出

- `output/demo_<file_id>/...`

### 告警输出

- `result/manifest.jsonl`
- `result/b.n/case.json`
- `result/b.n/request.txt`
- `result/b.n/response.txt`

---

## 7. 故障排查

### 总入口日志

- `output/app_runtime/app.log`

### 抓包日志

- `output/app_runtime/capture_stdout.log`
- `output/app_runtime/capture_stderr.log`

### 守护日志

- `output/app_runtime/daemon_stdout.log`
- `output/app_runtime/daemon_stderr.log`

### 单文件流程日志

- `output/daemon_runs/*.log`

---

## 8. 下一阶段对接建议

当接入大模型时，建议新增模块：

- `services/llm_analyzer.py`
- `services/enrichment.py`
- `api/backend_service.py`

并约定输出 JSON 字段：

- src_ip
- dst_ip
- attack_type
- attack_path
- attack_time
- attack_target
- confidence
- mitigation
