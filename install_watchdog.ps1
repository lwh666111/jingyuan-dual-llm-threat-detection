param([string]$ProjectRoot = $PSScriptRoot)

$ErrorActionPreference = "Stop"
$ProjectRoot = [System.IO.Path]::GetFullPath($ProjectRoot)
$watchdog = Join-Path $ProjectRoot "watchdog.ps1"
if (-not (Test-Path -LiteralPath $watchdog)) { throw "watchdog.ps1 not found: $watchdog" }

$taskName = "JTP-Main"
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument (
    "-NoProfile -ExecutionPolicy Bypass -File `"$watchdog`" -ProjectRoot `"$ProjectRoot`""
)
$startupTrigger = New-ScheduledTaskTrigger -AtStartup
$minuteTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1)
$triggers = @($startupTrigger, $minuteTrigger)
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 2)
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $triggers -Principal $principal -Settings $settings -Force | Out-Null
Write-Host "Installed watchdog task: $taskName"
