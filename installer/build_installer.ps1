param(
    [string]$IssFile = "installer/traffic_pipeline_setup.iss"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Find-Iscc {
    $cmd = Get-Command iscc -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }

    $candidates = @(
        "$env:ProgramFiles(x86)\Inno Setup 6\ISCC.exe",
        "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
        "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
    )
    foreach ($path in $candidates) {
        if (Test-Path -LiteralPath $path) { return $path }
    }
    throw "ISCC.exe not found. Please install Inno Setup 6 first."
}

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location -LiteralPath $projectRoot

if (-not (Test-Path -LiteralPath $IssFile)) {
    throw "ISS file not found: $IssFile"
}

$iscc = Find-Iscc
Write-Host "Using ISCC: $iscc" -ForegroundColor Cyan
Write-Host "Building installer..." -ForegroundColor Cyan

& $iscc "/DSourceRoot=$projectRoot" "$IssFile"
if ($LASTEXITCODE -ne 0) {
    throw "ISCC compile failed."
}

Write-Host ""
Write-Host "Build complete. Output in: $projectRoot\dist" -ForegroundColor Green
Get-ChildItem -LiteralPath (Join-Path $projectRoot "dist") -Filter "*.exe" | Select-Object Name,Length,LastWriteTime | Format-Table -AutoSize
