# `scripts/run_capture_compare_admin_once.ps1` 逐行注释

**脚本用途：** 辅助脚本：根据文件名 `run_capture_compare_admin_once.ps1` 完成对应的数据处理或运维任务。

**源码行数：** 52　**函数/类数量：** 0

| 行号 | 中文说明 | 原始源码 |
|---:|---|---|
| L0001 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>param(</code> |
| L0002 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>  [string]$ProjectRoot = 'C:\Users\lenovo\Desktop\deeplearning\traffic_pipeline',</code> |
| L0003 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>  [string]$LogPath = '',</code> |
| L0004 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>  [int]$Attacks = 30,</code> |
| L0005 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>  [int]$Benign = 30,</code> |
| L0006 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>  [int]$CaptureBatchSize = 20,</code> |
| L0007 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>  [string]$Interface = '1',</code> |
| L0008 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>  [int]$CaptureTimeoutSeconds = 420,</code> |
| L0009 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>  [int]$CaptureReadyTimeoutSeconds = 90,</code> |
| L0010 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>  [int]$RequestIntervalMs = 25</code> |
| L0011 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>)</code> |
| L0012 | 判断条件是否成立，成立时进入对应处理分支。 | <code>if ([string]::IsNullOrWhiteSpace($LogPath)) {</code> |
| L0013 | 执行 PowerShell 配置或变量操作：&#96;$LogPath = Join-Path $ProjectRoot ('output\real_capture_threshold_compare\admin_&#96;。 | <code>  $LogPath = Join-Path $ProjectRoot ('output\real_capture_threshold_compare\admin_quick_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.log')</code> |
| L0014 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>}</code> |
| L0015 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>New-Item -ItemType Directory -Force -Path (Split-Path $LogPath -Parent) &#124; Out-Null</code> |
| L0016 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>"[START] $(Get-Date -Format s)" &#124; Out-File -FilePath $LogPath -Encoding utf8</code> |
| L0017 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0018 | 源码原注释：cleanup stale capture/eval processes from previous failed elevated runs | <code># cleanup stale capture/eval processes from previous failed elevated runs</code> |
| L0019 | 执行 PowerShell 配置或变量操作：&#96;$patterns = @('real_capture_threshold_compare.py','capture_http_request_batches.&#96;。 | <code>$patterns = @('real_capture_threshold_compare.py','capture_http_request_batches.py')</code> |
| L0020 | 执行 PowerShell 配置或变量操作：&#96;$procs = Get-CimInstance Win32_Process -Filter "Name='python.exe'"&#96;。 | <code>$procs = Get-CimInstance Win32_Process -Filter "Name='python.exe'"</code> |
| L0021 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>foreach ($p in $procs) {</code> |
| L0022 | 执行 PowerShell 配置或变量操作：&#96;$cmd = [string]$p.CommandLine&#96;。 | <code>  $cmd = [string]$p.CommandLine</code> |
| L0023 | 判断条件是否成立，成立时进入对应处理分支。 | <code>  if ([string]::IsNullOrWhiteSpace($cmd)) { continue }</code> |
| L0024 | 执行 PowerShell 配置或变量操作：&#96;$hit = $false&#96;。 | <code>  $hit = $false</code> |
| L0025 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>  foreach ($pat in $patterns) { if ($cmd -like "*$pat*") { $hit = $true; break } }</code> |
| L0026 | 判断条件是否成立，成立时进入对应处理分支。 | <code>  if ($hit) {</code> |
| L0027 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    try { Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop; "[CLEANUP] killed python pid=$($p.ProcessId)" &#124; Out-File -FilePath $LogPath -Append -Encoding utf8 } catch { "[CLEANUP] failed pid=$($p.ProcessId) $($_.Exception.Message)" &#124; Out-File -FilePath $LogPath -Append -Encoding utf8 }</code> |
| L0028 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>  }</code> |
| L0029 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>}</code> |
| L0030 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>try { Get-Process tshark -ErrorAction SilentlyContinue &#124; Stop-Process -Force -ErrorAction Stop; "[CLEANUP] killed tshark" &#124; Out-File -FilePath $LogPath -Append -Encoding utf8 } catch { "[CLEANUP] tshark skip $($_.Exception.Message)" &#124; Out-File -FilePath $LogPath -Append -Encoding utf8 }</code> |
| L0031 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0032 | 执行 PowerShell 配置或变量操作：&#96;$script = Join-Path $ProjectRoot 'scripts\real_capture_threshold_compare.py'&#96;。 | <code>$script = Join-Path $ProjectRoot 'scripts\real_capture_threshold_compare.py'</code> |
| L0033 | 执行 PowerShell 配置或变量操作：&#96;$py = 'python'&#96;。 | <code>$py = 'python'</code> |
| L0034 | 执行 PowerShell 配置或变量操作：&#96;$args = @(&#96;。 | <code>$args = @(</code> |
| L0035 | 执行 PowerShell 配置或变量操作：&#96;$script,&#96;。 | <code>  $script,</code> |
| L0036 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>  '--project-root',"$ProjectRoot",</code> |
| L0037 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>  '--host','127.0.0.1',</code> |
| L0038 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>  '--port','3000',</code> |
| L0039 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>  '--interface',"$Interface",</code> |
| L0040 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>  '--attacks',"$Attacks",</code> |
| L0041 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>  '--benign',"$Benign",</code> |
| L0042 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>  '--capture-batch-size',"$CaptureBatchSize",</code> |
| L0043 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>  '--capture-timeout-seconds',"$CaptureTimeoutSeconds",</code> |
| L0044 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>  '--capture-ready-timeout-seconds',"$CaptureReadyTimeoutSeconds",</code> |
| L0045 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>  '--request-interval-ms',"$RequestIntervalMs",</code> |
| L0046 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>  '--thresholds','0.79,0.46'</code> |
| L0047 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>)</code> |
| L0048 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>"[CMD] $py $($args -join ' ')" &#124; Out-File -FilePath $LogPath -Append -Encoding utf8</code> |
| L0049 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>&amp; $py @args 2&gt;&amp;1 &#124; Out-File -FilePath $LogPath -Append -Encoding utf8</code> |
| L0050 | 执行 PowerShell 配置或变量操作：&#96;$code = $LASTEXITCODE&#96;。 | <code>$code = $LASTEXITCODE</code> |
| L0051 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>"[END] $(Get-Date -Format s) EXIT=$code" &#124; Out-File -FilePath $LogPath -Append -Encoding utf8</code> |
| L0052 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>exit $code</code> |
