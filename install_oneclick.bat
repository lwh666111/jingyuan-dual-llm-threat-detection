@echo off
setlocal
cd /d "%~dp0"
echo [traffic_pipeline] One-click installer starting...
powershell -NoProfile -ExecutionPolicy Bypass -File ".\deploy\start_all_nodocker.ps1" %*
set EXIT_CODE=%ERRORLEVEL%
if not "%EXIT_CODE%"=="0" (
  echo.
  echo [traffic_pipeline] Installer failed with exit code %EXIT_CODE%.
  pause
)
endlocal
