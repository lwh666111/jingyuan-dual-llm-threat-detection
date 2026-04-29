param(
    [string]$EnvFile = "deploy/.env.nodocker",
    [string]$PythonExe = "python",
    [switch]$NoInstallDeps,
    [switch]$NoInstallNode,
    [switch]$NoInstallWireshark,
    [switch]$NoInstallOllama,
    [switch]$NoModelPull,
    [switch]$NoStartApp,
    [switch]$SeedDemoData
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Ensure-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($isAdmin) { return }

    $rawArgs = @()
    foreach ($arg in $MyInvocation.UnboundArguments) {
        $rawArgs += $arg
    }
    $argList = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", "`"$PSCommandPath`""
    ) + $rawArgs

    Write-Host "Relaunching as Administrator..." -ForegroundColor Yellow
    Start-Process -FilePath "powershell" -Verb RunAs -ArgumentList $argList | Out-Null
    exit 0
}

function Load-EnvFile {
    param([string]$Path)
    $map = @{}
    if (-not (Test-Path -LiteralPath $Path)) {
        return $map
    }
    Get-Content -LiteralPath $Path | ForEach-Object {
        $line = $_.Trim()
        if (-not $line) { return }
        if ($line.StartsWith("#")) { return }
        $idx = $line.IndexOf("=")
        if ($idx -lt 1) { return }
        $key = $line.Substring(0, $idx).Trim()
        $val = $line.Substring($idx + 1).Trim()
        $map[$key] = $val
        [Environment]::SetEnvironmentVariable($key, $val, "Process")
    }
    return $map
}

function Ensure-PathEntry {
    param([string]$PathEntry)
    if (-not $PathEntry) { return }
    if (-not (Test-Path -LiteralPath $PathEntry)) { return }
    $current = $env:Path -split ";"
    if ($current -contains $PathEntry) { return }
    $env:Path = "$env:Path;$PathEntry"
}

function Ensure-Command {
    param(
        [string]$Name,
        [string]$Hint = ""
    )
    if (Get-Command $Name -ErrorAction SilentlyContinue) { return }
    if ($Hint) {
        throw "Command '$Name' not found. $Hint"
    }
    throw "Command '$Name' not found."
}

function Install-WithWinget {
    param(
        [string]$PackageId,
        [string]$DisplayName
    )
    Ensure-Command -Name "winget" -Hint "Please install App Installer / winget first."

    Write-Host "Installing $DisplayName via winget ($PackageId) ..." -ForegroundColor Cyan
    & winget install --id $PackageId --exact --accept-package-agreements --accept-source-agreements --silent --disable-interactivity
    if ($LASTEXITCODE -ne 0) {
        throw "winget install failed for $DisplayName ($PackageId)."
    }
}

function Wait-OllamaReady {
    param(
        [int]$Port,
        [int]$TimeoutSec = 180
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        try {
            Invoke-RestMethod -Uri "http://127.0.0.1:$Port/api/tags" -Method Get -TimeoutSec 3 | Out-Null
            return
        } catch { }
        Start-Sleep -Seconds 2
    }
    throw "Ollama was not ready within ${TimeoutSec}s: 127.0.0.1:$Port"
}

Ensure-Admin

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location -LiteralPath $projectRoot

if (-not (Test-Path -LiteralPath $EnvFile)) {
    Copy-Item -LiteralPath "deploy/.env.nodocker.example" -Destination $EnvFile
    Write-Host "Generated $EnvFile." -ForegroundColor Yellow
    Write-Host "Please edit MySQL settings first, then run again." -ForegroundColor Yellow
    exit 0
}

$envMap = Load-EnvFile -Path $EnvFile

$mysqlHost = if ($envMap.ContainsKey("MYSQL_HOST")) { $envMap["MYSQL_HOST"] } else { "127.0.0.1" }
$mysqlPort = if ($envMap.ContainsKey("MYSQL_PORT")) { [int]$envMap["MYSQL_PORT"] } else { 3306 }
$mysqlUser = if ($envMap.ContainsKey("MYSQL_USER")) { $envMap["MYSQL_USER"] } else { "root" }
$mysqlPassword = if ($envMap.ContainsKey("MYSQL_PASSWORD")) { $envMap["MYSQL_PASSWORD"] } else { "123456" }
$mysqlDatabase = if ($envMap.ContainsKey("MYSQL_DATABASE")) { $envMap["MYSQL_DATABASE"] } else { "traffic_pipeline" }
$ollamaPort = if ($envMap.ContainsKey("OLLAMA_PORT")) { [int]$envMap["OLLAMA_PORT"] } else { 11434 }
$ollamaModel = if ($envMap.ContainsKey("OLLAMA_MODEL")) { $envMap["OLLAMA_MODEL"] } else { "qwen3:8b" }
$monitorPorts = if ($envMap.ContainsKey("MONITOR_PORTS")) { $envMap["MONITOR_PORTS"] } else { "3000" }
$captureBatchSize = if ($envMap.ContainsKey("CAPTURE_BATCH_SIZE")) { $envMap["CAPTURE_BATCH_SIZE"] } else { "1" }
$apiPort = if ($envMap.ContainsKey("API_PORT")) { [int]$envMap["API_PORT"] } else { 3049 }
$dashboardPort = if ($envMap.ContainsKey("DASHBOARD_PORT")) { [int]$envMap["DASHBOARD_PORT"] } else { 1145 }

Ensure-PathEntry -PathEntry "$env:ProgramFiles\nodejs"
Ensure-PathEntry -PathEntry "$env:ProgramFiles\Wireshark"
Ensure-PathEntry -PathEntry "$env:LOCALAPPDATA\Programs\Ollama"

Ensure-Command -Name $PythonExe -Hint "Please install Python 3.10+ and add it to PATH."

if (-not $NoInstallNode) {
    if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
        Install-WithWinget -PackageId "OpenJS.NodeJS.LTS" -DisplayName "Node.js LTS"
        Ensure-PathEntry -PathEntry "$env:ProgramFiles\nodejs"
    }
}

if (-not $NoInstallWireshark) {
    if (-not (Get-Command tshark -ErrorAction SilentlyContinue)) {
        Install-WithWinget -PackageId "WiresharkFoundation.Wireshark" -DisplayName "Wireshark + TShark"
        Ensure-PathEntry -PathEntry "$env:ProgramFiles\Wireshark"
    }
}

if (-not $NoInstallOllama) {
    if (-not (Get-Command ollama -ErrorAction SilentlyContinue)) {
        Install-WithWinget -PackageId "Ollama.Ollama" -DisplayName "Ollama"
        Ensure-PathEntry -PathEntry "$env:LOCALAPPDATA\Programs\Ollama"
    }
}

if (-not $NoInstallDeps) {
    Write-Host "[1/6] Installing Python dependencies..." -ForegroundColor Cyan
    & $PythonExe -m pip install -r "requirements.txt"
}

Write-Host "[2/6] Building RAG SQLite DB..." -ForegroundColor Cyan
& $PythonExe "scripts/build_rag_db.py" --seed-file "llm/rag/rag_seed.json" --db-path "llm/rag/rag_knowledge.db"

if (-not (Get-Command ollama -ErrorAction SilentlyContinue)) {
    throw "ollama command not found. Install Ollama first, or rerun without -NoInstallOllama."
}

Write-Host "[3/6] Starting Ollama service..." -ForegroundColor Cyan
$ollamaProc = Get-Process -Name "ollama" -ErrorAction SilentlyContinue
if (-not $ollamaProc) {
    Start-Process -FilePath "ollama" -ArgumentList "serve" -WindowStyle Hidden | Out-Null
}
Wait-OllamaReady -Port $ollamaPort

if (-not $NoModelPull) {
    Write-Host "[4/6] Pulling model: $ollamaModel ..." -ForegroundColor Cyan
    & ollama pull $ollamaModel
}

Write-Host "[5/6] Verifying MySQL connectivity and writing runtime capture config..." -ForegroundColor Cyan
$pyInit = @'
import sys
import pymysql

host = sys.argv[1]
port = int(sys.argv[2])
user = sys.argv[3]
password = sys.argv[4]
database = sys.argv[5]
monitor_ports = sys.argv[6]
capture_batch_size = sys.argv[7]

conn = pymysql.connect(
    host=host,
    port=port,
    user=user,
    password=password,
    charset="utf8mb4",
    autocommit=True,
)
try:
    with conn.cursor() as cur:
        cur.execute(f"CREATE DATABASE IF NOT EXISTS `{database}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
finally:
    conn.close()

conn = pymysql.connect(
    host=host,
    port=port,
    user=user,
    password=password,
    database=database,
    charset="utf8mb4",
    autocommit=True,
)
try:
    with conn.cursor() as cur:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS demo_system_config (
              config_key VARCHAR(64) PRIMARY KEY,
              config_value VARCHAR(256) NOT NULL,
              updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
            """
        )
        cur.execute(
            "INSERT INTO demo_system_config(config_key, config_value) VALUES (%s, %s) "
            "ON DUPLICATE KEY UPDATE config_value=VALUES(config_value)",
            ("monitor_ports", monitor_ports),
        )
        cur.execute(
            "INSERT INTO demo_system_config(config_key, config_value) VALUES (%s, %s) "
            "ON DUPLICATE KEY UPDATE config_value=VALUES(config_value)",
            ("capture_batch_size", capture_batch_size),
        )
finally:
    conn.close()

print("mysql_init_ok")
'@
$pyInit | & $PythonExe - $mysqlHost $mysqlPort $mysqlUser $mysqlPassword $mysqlDatabase $monitorPorts $captureBatchSize
if ($LASTEXITCODE -ne 0) {
    throw "MySQL init failed. Please verify MYSQL_* in $EnvFile."
}

if ($NoStartApp) {
    Write-Host "Initialization done. Skip app startup because -NoStartApp is set." -ForegroundColor Green
    exit 0
}

$existing = Get-CimInstance Win32_Process | Where-Object {
    $_.Name -match "python|node" -and $_.CommandLine -match "traffic_pipeline" -and
    ($_.CommandLine -match "app.py|capture_http_request_batches|run_demo_daemon|result_db_daemon|dashboard_api_server|frontend_dashboard\\server.js")
}
foreach ($p in $existing) {
    try { Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop } catch { }
}

$firstPort = (($monitorPorts -split ",")[0]).Trim()
if (-not $firstPort) { $firstPort = "80" }

Write-Host "[6/6] Launching app.py ..." -ForegroundColor Cyan
$appArgs = @(
    "app.py",
    "--python-exe", $PythonExe,
    "--node-exe", "node",
    "--db-backend", "mysql",
    "--mysql-host", $mysqlHost,
    "--mysql-port", "$mysqlPort",
    "--mysql-user", $mysqlUser,
    "--mysql-password", $mysqlPassword,
    "--mysql-database", $mysqlDatabase,
    "--api-port", "$apiPort",
    "--dashboard-port", "$dashboardPort",
    "--port", "$firstPort",
    "--ports", "$monitorPorts",
    "--capture-batch-size", "$captureBatchSize",
    "--ollama-url", "http://127.0.0.1:$ollamaPort",
    "--llm-model", "$ollamaModel",
    "--no-api-seed-demo"
)
if ($SeedDemoData) {
    $appArgs = $appArgs | Where-Object { $_ -ne "--no-api-seed-demo" }
    $appArgs += "--api-seed-demo"
}

Start-Process -FilePath $PythonExe -ArgumentList $appArgs -WorkingDirectory $projectRoot | Out-Null

Write-Host ""
Write-Host "No-Docker one-click deployment finished." -ForegroundColor Green
Write-Host "Dashboard: http://127.0.0.1:$dashboardPort"
Write-Host "API:       http://127.0.0.1:$apiPort"
Write-Host "Ollama:    http://127.0.0.1:$ollamaPort"
Write-Host "MySQL:     ${mysqlHost}:$mysqlPort ($mysqlUser / configured password)"
Write-Host ""
Write-Host "If packet capture is needed, keep running with Administrator privileges." -ForegroundColor Yellow
