param(
    [string]$EnvFile = "deploy/.env",
    [string]$PythonExe = "python",
    [switch]$NoModelPull,
    [switch]$NoLlm,
    [switch]$SeedDemoData
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

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

function Wait-MySqlReady {
    param(
        [string]$Container,
        [string]$Password,
        [int]$TimeoutSec = 180
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        try {
            docker exec $Container mysqladmin ping -h 127.0.0.1 -uroot "-p$Password" --silent | Out-Null
            if ($LASTEXITCODE -eq 0) { return }
        } catch { }
        Start-Sleep -Seconds 2
    }
    throw "MySQL was not ready within ${TimeoutSec}s: $Container"
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

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location -LiteralPath $projectRoot

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw "docker command not found. Please install and start Docker Desktop first."
}
docker compose version | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "docker compose is unavailable. Please enable Docker Compose in Docker Desktop."
}

if (-not (Test-Path -LiteralPath $EnvFile)) {
    Copy-Item -LiteralPath "deploy/.env.example" -Destination $EnvFile
    Write-Host "Generated $EnvFile. Edit it if needed, then run again." -ForegroundColor Yellow
    exit 0
}

$envMap = Load-EnvFile -Path $EnvFile

$mysqlContainer = if ($envMap.ContainsKey("MYSQL_CONTAINER_NAME")) { $envMap["MYSQL_CONTAINER_NAME"] } else { "traffic_pipeline_mysql" }
$mysqlPassword = if ($envMap.ContainsKey("MYSQL_ROOT_PASSWORD")) { $envMap["MYSQL_ROOT_PASSWORD"] } else { "123456" }
$mysqlDatabase = if ($envMap.ContainsKey("MYSQL_DATABASE")) { $envMap["MYSQL_DATABASE"] } else { "traffic_pipeline" }
$mysqlPort = if ($envMap.ContainsKey("MYSQL_PORT")) { [int]$envMap["MYSQL_PORT"] } else { 3306 }
$ollamaPort = if ($envMap.ContainsKey("OLLAMA_PORT")) { [int]$envMap["OLLAMA_PORT"] } else { 11434 }
$ollamaModel = if ($envMap.ContainsKey("OLLAMA_MODEL")) { $envMap["OLLAMA_MODEL"] } else { "qwen3:8b" }
$monitorPorts = if ($envMap.ContainsKey("MONITOR_PORTS")) { $envMap["MONITOR_PORTS"] } else { "3000" }
$captureBatchSize = if ($envMap.ContainsKey("CAPTURE_BATCH_SIZE")) { $envMap["CAPTURE_BATCH_SIZE"] } else { "1" }
$apiPort = if ($envMap.ContainsKey("API_PORT")) { [int]$envMap["API_PORT"] } else { 3049 }
$dashboardPort = if ($envMap.ContainsKey("DASHBOARD_PORT")) { [int]$envMap["DASHBOARD_PORT"] } else { 1145 }

Write-Host "[1/7] Starting infra containers (MySQL + Ollama)..." -ForegroundColor Cyan
docker compose --env-file $EnvFile -f "deploy/docker-compose.infra.yml" up -d mysql ollama | Out-Null

Write-Host "[2/7] Waiting for MySQL..." -ForegroundColor Cyan
Wait-MySqlReady -Container $mysqlContainer -Password $mysqlPassword

Write-Host "[3/7] Waiting for Ollama..." -ForegroundColor Cyan
Wait-OllamaReady -Port $ollamaPort

if (-not $NoModelPull) {
    Write-Host "[4/7] Pulling Ollama model: $ollamaModel ..." -ForegroundColor Cyan
    $pullBody = @{ model = $ollamaModel; stream = $false } | ConvertTo-Json -Compress
    Invoke-RestMethod -Uri "http://127.0.0.1:$ollamaPort/api/pull" -Method Post -ContentType "application/json" -Body $pullBody | Out-Null
}

Write-Host "[5/7] Building RAG SQLite database..." -ForegroundColor Cyan
& $PythonExe "scripts/build_rag_db.py" --seed-file "llm/rag/rag_seed.json" --db-path "llm/rag/rag_knowledge.db"

Write-Host "[6/7] Installing/checking Python dependencies..." -ForegroundColor Cyan
& $PythonExe -m pip install -r "requirements.txt" | Out-Null

Write-Host "[7/7] Injecting runtime config and launching app.py ..." -ForegroundColor Cyan
$sql = @"
CREATE TABLE IF NOT EXISTS demo_system_config (
  config_key VARCHAR(64) PRIMARY KEY,
  config_value VARCHAR(256) NOT NULL,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
INSERT INTO demo_system_config(config_key, config_value)
VALUES ('monitor_ports', '$monitorPorts')
ON DUPLICATE KEY UPDATE config_value=VALUES(config_value);
INSERT INTO demo_system_config(config_key, config_value)
VALUES ('capture_batch_size', '$captureBatchSize')
ON DUPLICATE KEY UPDATE config_value=VALUES(config_value);
"@
docker exec $mysqlContainer mysql -uroot "-p$mysqlPassword" -D $mysqlDatabase -e $sql | Out-Null

$existing = Get-CimInstance Win32_Process | Where-Object {
    $_.Name -match "python|node" -and $_.CommandLine -match "traffic_pipeline" -and
    ($_.CommandLine -match "app.py|capture_http_request_batches|run_demo_daemon|result_db_daemon|dashboard_api_server|frontend_dashboard\\server.js")
}
foreach ($p in $existing) {
    try { Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop } catch { }
}

$appArgs = @(
    "app.py",
    "--db-backend", "mysql",
    "--mysql-host", "127.0.0.1",
    "--mysql-port", "$mysqlPort",
    "--mysql-user", "root",
    "--mysql-password", "$mysqlPassword",
    "--mysql-database", "$mysqlDatabase",
    "--api-port", "$apiPort",
    "--dashboard-port", "$dashboardPort",
    "--ollama-url", "http://127.0.0.1:$ollamaPort",
    "--llm-model", "$ollamaModel",
    "--no-api-seed-demo"
)

if ($NoLlm) {
    $appArgs += "--no-llm"
}
if ($SeedDemoData) {
    $appArgs = $appArgs | Where-Object { $_ -ne "--no-api-seed-demo" }
    $appArgs += "--api-seed-demo"
}

Start-Process -FilePath $PythonExe -ArgumentList $appArgs -WorkingDirectory $projectRoot | Out-Null

Write-Host ""
Write-Host "One-click deployment finished." -ForegroundColor Green
Write-Host "Dashboard: http://127.0.0.1:$dashboardPort"
Write-Host "API:       http://127.0.0.1:$apiPort"
Write-Host "Ollama:    http://127.0.0.1:$ollamaPort"
Write-Host "MySQL:     127.0.0.1:$mysqlPort  (root/$mysqlPassword)"
