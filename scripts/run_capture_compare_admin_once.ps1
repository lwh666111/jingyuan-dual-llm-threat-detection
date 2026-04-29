param(
  [string]$ProjectRoot = 'C:\Users\lenovo\Desktop\deeplearning\traffic_pipeline',
  [string]$LogPath = '',
  [int]$Attacks = 30,
  [int]$Benign = 30,
  [int]$CaptureBatchSize = 20,
  [string]$Interface = '1',
  [int]$CaptureTimeoutSeconds = 420,
  [int]$CaptureReadyTimeoutSeconds = 90,
  [int]$RequestIntervalMs = 25
)
if ([string]::IsNullOrWhiteSpace($LogPath)) {
  $LogPath = Join-Path $ProjectRoot ('output\real_capture_threshold_compare\admin_quick_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.log')
}
New-Item -ItemType Directory -Force -Path (Split-Path $LogPath -Parent) | Out-Null
"[START] $(Get-Date -Format s)" | Out-File -FilePath $LogPath -Encoding utf8

# cleanup stale capture/eval processes from previous failed elevated runs
$patterns = @('real_capture_threshold_compare.py','capture_http_request_batches.py')
$procs = Get-CimInstance Win32_Process -Filter "Name='python.exe'"
foreach ($p in $procs) {
  $cmd = [string]$p.CommandLine
  if ([string]::IsNullOrWhiteSpace($cmd)) { continue }
  $hit = $false
  foreach ($pat in $patterns) { if ($cmd -like "*$pat*") { $hit = $true; break } }
  if ($hit) {
    try { Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop; "[CLEANUP] killed python pid=$($p.ProcessId)" | Out-File -FilePath $LogPath -Append -Encoding utf8 } catch { "[CLEANUP] failed pid=$($p.ProcessId) $($_.Exception.Message)" | Out-File -FilePath $LogPath -Append -Encoding utf8 }
  }
}
try { Get-Process tshark -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction Stop; "[CLEANUP] killed tshark" | Out-File -FilePath $LogPath -Append -Encoding utf8 } catch { "[CLEANUP] tshark skip $($_.Exception.Message)" | Out-File -FilePath $LogPath -Append -Encoding utf8 }

$script = Join-Path $ProjectRoot 'scripts\real_capture_threshold_compare.py'
$py = 'python'
$args = @(
  $script,
  '--project-root',"$ProjectRoot",
  '--host','127.0.0.1',
  '--port','3000',
  '--interface',"$Interface",
  '--attacks',"$Attacks",
  '--benign',"$Benign",
  '--capture-batch-size',"$CaptureBatchSize",
  '--capture-timeout-seconds',"$CaptureTimeoutSeconds",
  '--capture-ready-timeout-seconds',"$CaptureReadyTimeoutSeconds",
  '--request-interval-ms',"$RequestIntervalMs",
  '--thresholds','0.79,0.46'
)
"[CMD] $py $($args -join ' ')" | Out-File -FilePath $LogPath -Append -Encoding utf8
& $py @args 2>&1 | Out-File -FilePath $LogPath -Append -Encoding utf8
$code = $LASTEXITCODE
"[END] $(Get-Date -Format s) EXIT=$code" | Out-File -FilePath $LogPath -Append -Encoding utf8
exit $code
