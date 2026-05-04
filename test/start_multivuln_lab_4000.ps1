param(
    [string]$BindHost = "0.0.0.0",
    [int]$Port = 4000,
    [string]$PythonExe = ""
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($PythonExe)) {
    $PythonExe = "python"
}

$scriptPath = Join-Path $projectRoot "scripts\target_multivuln_lab.py"
if (-not (Test-Path -LiteralPath $scriptPath)) {
    throw "target script not found: $scriptPath"
}

$logDir = Join-Path $projectRoot "output\target_lab"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$stdoutLog = Join-Path $logDir "multivuln_4000_stdout.log"
$stderrLog = Join-Path $logDir "multivuln_4000_stderr.log"

$existing = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty OwningProcess -Unique
if ($existing) {
    Write-Host "port $Port already in use by pid(s): $($existing -join ',')" -ForegroundColor Yellow
    return
}

$argList = @($scriptPath, "--host", $BindHost, "--port", "$Port")
$proc = Start-Process -FilePath $PythonExe -ArgumentList $argList -WorkingDirectory $projectRoot -WindowStyle Hidden -RedirectStandardOutput $stdoutLog -RedirectStandardError $stderrLog -PassThru
Write-Host "target_multivuln_lab started pid=$($proc.Id) port=$Port"
Write-Host "stdout: $stdoutLog"
Write-Host "stderr: $stderrLog"

