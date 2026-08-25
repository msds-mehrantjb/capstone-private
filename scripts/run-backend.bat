@echo off
setlocal EnableExtensions

set "ROOT_DIR=%~dp0.."
for %%I in ("%ROOT_DIR%") do set "ROOT_DIR=%%~fI"

if not defined CAPSTONE_API_HOST set "CAPSTONE_API_HOST=127.0.0.1"
if not defined CAPSTONE_API_PORT set "CAPSTONE_API_PORT=8003"

set "VENV_PYTHON=%ROOT_DIR%\venv\Scripts\python.exe"
set "UVICORN_ARGS=app.main:app --host %CAPSTONE_API_HOST% --port %CAPSTONE_API_PORT%"
if /I "%CAPSTONE_ENABLE_RELOAD%"=="1" set "UVICORN_ARGS=%UVICORN_ARGS% --reload"

call :ensure_docker
if errorlevel 1 goto :startup_failed

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
exit /b 0


:ensure_docker
where docker >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Docker CLI is not installed or is not available in PATH.
  echo Install Docker Desktop, then run this script again.
  exit /b 1
)

docker info >nul 2>&1
if not errorlevel 1 (
  echo [OK] Docker Engine is running.
  exit /b 0
)

set "DOCKER_DESKTOP=%ProgramFiles%\Docker\Docker\Docker Desktop.exe"
if not exist "%DOCKER_DESKTOP%" set "DOCKER_DESKTOP=%LocalAppData%\Docker\Docker Desktop.exe"

if not exist "%DOCKER_DESKTOP%" (
  echo [ERROR] Docker is installed, but Docker Desktop.exe was not found.
  echo Start Docker Desktop manually, then run this script again.
  exit /b 1
)

echo [INFO] Docker Engine is not responding. Starting Docker Desktop before backend startup...
start "" "%DOCKER_DESKTOP%"

echo [INFO] Waiting for Docker Engine to become ready...
for /L %%I in (1,1,60) do (
  docker info >nul 2>&1
  if not errorlevel 1 (
    echo [OK] Docker Engine is ready.
    exit /b 0
  )
  timeout /t 2 /nobreak >nul
)

echo [ERROR] Docker Engine did not become ready, so the backend was not started.
echo Open Docker Desktop, wait until the engine is running, then run scripts\run-backend.bat again.
echo.
echo Docker diagnostic:
docker info 2>&1
exit /b 1


:startup_failed
echo.
echo Backend startup stopped because Docker is not ready.
pause
exit /b 1
