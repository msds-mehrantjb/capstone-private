@echo off
setlocal

set "ROOT_DIR=%~dp0.."
for %%I in ("%ROOT_DIR%") do set "ROOT_DIR=%%~fI"

echo Starting Full System...
echo Project root: %ROOT_DIR%
echo.

echo Closing any existing Capstone dev servers on ports 8002 and 5174...
for %%P in (8002 5174) do (
  for /f "tokens=5" %%A in ('netstat -ano ^| findstr /R /C:":%%P .*LISTENING"') do (
    echo Stopping process %%A on port %%P
    taskkill /PID %%A /F >nul 2>&1
  )
)

echo.
echo Starting backend and frontend in separate windows...

start "Capstone Backend" /D "%ROOT_DIR%" cmd /k ""%ROOT_DIR%\venv\Scripts\python.exe" -m uvicorn app.main:app --reload --port 8002"
start "Capstone Frontend" /D "%ROOT_DIR%\app" cmd /k "npm run dev -- --host localhost --port 5174"

echo Backend started on http://localhost:8002
echo Frontend started on http://localhost:5174
pause
