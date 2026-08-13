param(
    [string]$ProjectRoot = $PSScriptRoot,
    [int]$HeartbeatTimeoutSeconds = 90,
    [int]$UnhealthyTimeoutSeconds = 180
)

$ErrorActionPreference = "Stop"
$ProjectRoot = [System.IO.Path]::GetFullPath($ProjectRoot)
$statePath = Join-Path $ProjectRoot "output\app_runtime\app_state.json"
$logPath = Join-Path $ProjectRoot "output\app_runtime\watchdog.log"
$unhealthyMarker = Join-Path $ProjectRoot "output\app_runtime\watchdog_unhealthy_since.txt"
$python = "C:\python\python312\python.exe"
if (-not (Test-Path -LiteralPath $python)) { $python = "python" }

function Write-WatchdogLog([string]$Message) {
    $dir = Split-Path -Parent $logPath
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $line = "[$(Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')] $Message"
    Add-Content -LiteralPath $logPath -Value $line -Encoding UTF8
}

$escapedRoot = [Regex]::Escape($ProjectRoot)
$main = Get-CimInstance Win32_Process -Filter "Name='python.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -match $escapedRoot -and $_.CommandLine -match 'app\.py' } |
    Select-Object -First 1

$heartbeatFresh = $false
$reportedHealthy = $false
if (Test-Path -LiteralPath $statePath) {
    try {
        $state = Get-Content -LiteralPath $statePath -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($state.heartbeat_at) {
            $age = ((Get-Date) - [datetime]$state.heartbeat_at).TotalSeconds
            $heartbeatFresh = $age -le $HeartbeatTimeoutSeconds
            $reportedHealthy = $state.healthy -eq $true
        }
    } catch {
        Write-WatchdogLog "state parse failed: $($_.Exception.Message)"
    }
}

if ($main -and $heartbeatFresh -and $reportedHealthy) {
    Remove-Item -LiteralPath $unhealthyMarker -Force -ErrorAction SilentlyContinue
    exit 0
}

if ($main -and $heartbeatFresh -and -not $reportedHealthy) {
    $now = Get-Date
    $unhealthySince = $now
    if (Test-Path -LiteralPath $unhealthyMarker) {
        try { $unhealthySince = [datetime](Get-Content -LiteralPath $unhealthyMarker -Raw -Encoding UTF8) } catch {}
    } else {
        $now.ToString("o") | Set-Content -LiteralPath $unhealthyMarker -Encoding UTF8
    }
    $unhealthyAge = ($now - $unhealthySince).TotalSeconds
    if ($unhealthyAge -lt $UnhealthyTimeoutSeconds) {
        Write-WatchdogLog "component unhealthy for $([int]$unhealthyAge)s; app supervisor is still repairing it"
        exit 0
    }
}

if ($main -and (-not $heartbeatFresh -or -not $reportedHealthy)) {
    Write-WatchdogLog "main unhealthy or heartbeat stale; stopping pid=$($main.ProcessId)"
    Stop-Process -Id $main.ProcessId -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3
}
Remove-Item -LiteralPath $unhealthyMarker -Force -ErrorAction SilentlyContinue

$app = Join-Path $ProjectRoot "app.py"
if (-not (Test-Path -LiteralPath $app)) {
    Write-WatchdogLog "app.py missing; restart skipped"
    exit 2
}

Write-WatchdogLog "starting the only production instance from $ProjectRoot"
Start-Process -FilePath $python -WorkingDirectory $ProjectRoot -ArgumentList @(
    $app, "--mysql-port", "3307", "--auto-start-lab", "--test-lab-host", "0.0.0.0", "--test-lab-port", "4000"
) -WindowStyle Normal
