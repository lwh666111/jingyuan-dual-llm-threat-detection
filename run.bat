@echo off
chcp 65001 >nul
title Jingyuan Traffic Pipeline
cd /d "%~dp0"
python app.py --mysql-port 3306 --auto-start-lab --test-lab-host 0.0.0.0 --test-lab-port 4000
if errorlevel 1 pause
