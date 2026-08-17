@echo off
setlocal EnableExtensions

set "ROOT_DIR=%~dp0.."
for %%I in ("%ROOT_DIR%") do set "ROOT_DIR=%%~fI"

if not defined CAPSTONE_API_HOST set "CAPSTONE_API_HOST=127.0.0.1"
if not defined CAPSTONE_API_PORT set "CAPSTONE_API_PORT=8003"

set "VENV_PYTHON=%ROOT_DIR%\venv\Scripts\python.exe"
set "UVICORN_ARGS=app.main:app --host %CAPSTONE_API_HOST% --port %CAPSTONE_API_PORT%"
if /I "%CAPSTONE_ENABLE_RELOAD%"=="1" set "UVICORN_ARGS=%UVICORN_ARGS% --reload"

pushd "%ROOT_DIR%" || exit /b 1

echo Starting Backend on http://%CAPSTONE_API_HOST%:%CAPSTONE_API_PORT% ...
if /I "%CAPSTONE_ENABLE_RELOAD%"=="1" (
  echo Reload mode is ENABLED.
) else (
  echo Reload mode is DISABLED for startup stability on Windows.
)

"%VENV_PYTHON%" -m uvicorn %UVICORN_ARGS%

popd
pause
