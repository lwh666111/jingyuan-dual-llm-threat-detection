param(
    [string]$BindHost = "0.0.0.0",
    [int]$Port = 4000,
    [string]$PythonExe = "",
    [string]$MySqlHost = "",
    [int]$MySqlPort = 0,
    [string]$MySqlUser = "",
    [string]$MySqlPassword = "",
    [string]$MySqlDatabase = ""
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($PythonExe)) {
    $PythonExe = "python"
}

$dbConfigPath = Join-Path $projectRoot "config\db_config.json"
if (Test-Path -LiteralPath $dbConfigPath) {
    try {
        $dbConfig = Get-Content -LiteralPath $dbConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
        if ([string]::IsNullOrWhiteSpace($MySqlHost)) { $MySqlHost = [string]$dbConfig.mysql.host }
        if ($MySqlPort -le 0) { $MySqlPort = [int]$dbConfig.mysql.port }
        if ([string]::IsNullOrWhiteSpace($MySqlUser)) { $MySqlUser = [string]$dbConfig.mysql.user }
        if ([string]::IsNullOrWhiteSpace($MySqlPassword)) { $MySqlPassword = [string]$dbConfig.mysql.password }
        if ([string]::IsNullOrWhiteSpace($MySqlDatabase)) { $MySqlDatabase = [string]$dbConfig.mysql.database }
    } catch {
        Write-Host "warn: db_config.json read failed, fallback to env/defaults: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}
if ([string]::IsNullOrWhiteSpace($MySqlHost)) { $MySqlHost = if ($env:TP_MYSQL_HOST) { $env:TP_MYSQL_HOST } else { "127.0.0.1" } }
if ($MySqlPort -le 0) { $MySqlPort = if ($env:TP_MYSQL_PORT) { [int]$env:TP_MYSQL_PORT } else { 3306 } }
if ([string]::IsNullOrWhiteSpace($MySqlUser)) { $MySqlUser = if ($env:TP_MYSQL_USER) { $env:TP_MYSQL_USER } else { "root" } }
if ([string]::IsNullOrWhiteSpace($MySqlPassword)) { $MySqlPassword = if ($env:TP_MYSQL_PASSWORD) { $env:TP_MYSQL_PASSWORD } else { "123456" } }
if ([string]::IsNullOrWhiteSpace($MySqlDatabase)) { $MySqlDatabase = if ($env:TP_MYSQL_DATABASE) { $env:TP_MYSQL_DATABASE } else { "traffic_pipeline" } }

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

$argList = @(
    $scriptPath,
    "--host", $BindHost,
    "--port", "$Port",
    "--mysql-host", $MySqlHost,
    "--mysql-port", "$MySqlPort",
    "--mysql-user", $MySqlUser,
    "--mysql-password", $MySqlPassword,
    "--mysql-database", $MySqlDatabase
)
$proc = Start-Process -FilePath $PythonExe -ArgumentList $argList -WorkingDirectory $projectRoot -WindowStyle Hidden -RedirectStandardOutput $stdoutLog -RedirectStandardError $stderrLog -PassThru
Write-Host "target_multivuln_lab started pid=$($proc.Id) port=$Port"
Write-Host "mysql blocked-ip source: $MySqlHost`:$MySqlPort/$MySqlDatabase"
Write-Host "stdout: $stdoutLog"
Write-Host "stderr: $stderrLog"
