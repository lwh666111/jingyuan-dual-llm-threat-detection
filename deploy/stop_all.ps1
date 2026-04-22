param(
    [string]$EnvFile = "deploy/.env",
    [switch]$RemoveInfraData
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location -LiteralPath $projectRoot

$procs = Get-CimInstance Win32_Process | Where-Object {
    $_.Name -match "python|node" -and $_.CommandLine -match "traffic_pipeline" -and
    ($_.CommandLine -match "app.py|capture_http_request_batches|run_demo_daemon|result_db_daemon|dashboard_api_server|frontend_dashboard\\server.js")
}
foreach ($p in $procs) {
    try { Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop } catch { }
}

if (-not (Test-Path -LiteralPath $EnvFile)) {
    $EnvFile = "deploy/.env.example"
}

if (Get-Command docker -ErrorAction SilentlyContinue) {
    docker compose version | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "docker compose unavailable, skipped infra containers shutdown." -ForegroundColor Yellow
        Write-Host "All services stopped." -ForegroundColor Green
        exit 0
    }
    if ($RemoveInfraData) {
        docker compose --env-file $EnvFile -f "deploy/docker-compose.infra.yml" down -v
    } else {
        docker compose --env-file $EnvFile -f "deploy/docker-compose.infra.yml" stop
    }
} else {
    Write-Host "docker command not found, skipped infra containers shutdown." -ForegroundColor Yellow
}

Write-Host "All services stopped." -ForegroundColor Green
