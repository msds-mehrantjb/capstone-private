@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%list-docker-lab-ips.ps1" %*
exit /b %ERRORLEVEL%
