param(
    [int[]]$Ports = @(4000)
)

$ErrorActionPreference = "Continue"

foreach ($p in $Ports) {
    $pids = Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty OwningProcess -Unique
    if (-not $pids) {
        Write-Host "port ${p}: no listener"
        continue
    }
    foreach ($pid in $pids) {
        try {
            Stop-Process -Id $pid -Force -ErrorAction Stop
            Write-Host "port ${p}: stopped pid=$pid"
        } catch {
            Write-Host "port ${p}: failed to stop pid=$pid $_"
        }
    }
}
