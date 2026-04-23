@echo off
setlocal

set "ROOT_DIR=%~dp0.."
for %%I in ("%ROOT_DIR%") do set "ROOT_DIR=%%~fI"

echo Starting Full System...
echo Project root: %ROOT_DIR%
echo.

echo Closing any existing Capstone dev servers on ports 8000 and 5173...
for %%P in (8000 5173) do (
  for /f "tokens=5" %%A in ('netstat -ano ^| findstr /R /C:":%%P .*LISTENING"') do (
    echo Stopping process %%A on port %%P
    taskkill /PID %%A /F >nul 2>&1
  )
)

echo.
echo Starting backend and frontend in separate windows...

start "Capstone Backend" /D "%ROOT_DIR%" cmd /k ""%ROOT_DIR%\venv\Scripts\python.exe" -m uvicorn app.main:app --reload"
start "Capstone Frontend" /D "%ROOT_DIR%\app" cmd /k "npm run dev"

echo Backend and Frontend started in separate windows.
pause
