@echo off
setlocal EnableExtensions

set "ROOT_DIR=%~dp0.."
for %%I in ("%ROOT_DIR%") do set "ROOT_DIR=%%~fI"

set "OLLAMA_MODEL=qwen3:14b"
set "OLLAMA_EMBED_MODEL=nomic-embed-text"

cls
echo ==============================================
echo Capstone Full System Startup
echo ==============================================
echo Project root: %ROOT_DIR%
echo.

echo [1/5] Checking Ollama...
call :ensure_ollama
if errorlevel 1 goto :startup_failed

echo.
echo [2/5] Checking required Ollama models...
call :ensure_ollama_model "%OLLAMA_MODEL%"
if errorlevel 1 goto :startup_failed
call :ensure_ollama_model "%OLLAMA_EMBED_MODEL%"
if errorlevel 1 goto :startup_failed

echo.
echo [3/5] Checking Docker Desktop / Docker Engine...
call :ensure_docker
if errorlevel 1 goto :startup_failed

echo.
echo [4/5] Closing existing Capstone dev servers on ports 8002 and 5174...
for %%P in (8002 5174) do (
  for /f "tokens=5" %%A in ('netstat -ano ^| findstr /R /C:":%%P .*LISTENING"') do (
    echo Stopping process %%A on port %%P
    taskkill /PID %%A /F >nul 2>&1
  )
)

echo.
echo [5/5] Starting backend and frontend in separate windows...
start "Capstone Backend" /D "%ROOT_DIR%" cmd /k ""%ROOT_DIR%\venv\Scripts\python.exe" -m uvicorn app.main:app --reload --port 8002"
start "Capstone Frontend" /D "%ROOT_DIR%\app" cmd /k "npm run dev -- --host localhost --port 5174"

echo.
echo ==============================================
echo Capstone startup completed
echo ==============================================
echo Ollama:  http://127.0.0.1:11434
echo Backend: http://localhost:8002
echo API Docs: http://localhost:8002/docs
echo Frontend: http://localhost:5174
echo Docker Engine: running
echo.
echo Note: Docker Desktop is started automatically when needed.
echo       The data\docker_lab containers are NOT automatically created or started.
echo.
pause
exit /b 0


:ensure_ollama
where ollama >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Ollama is not installed or is not available in PATH.
  echo Install Ollama for Windows, then run this script again.
  exit /b 1
)

call :ollama_health
if not errorlevel 1 (
  echo [OK] Ollama is already running.
  exit /b 0
)

echo [INFO] Ollama is installed but not responding. Starting Ollama server...
start "Ollama Service" /MIN cmd /c "ollama serve"

echo [INFO] Waiting for Ollama to become ready on http://127.0.0.1:11434 ...
for /L %%I in (1,1,30) do (
  call :ollama_health
  if not errorlevel 1 (
    echo [OK] Ollama is ready.
    exit /b 0
  )
  timeout /t 2 /nobreak >nul
)

echo [ERROR] Ollama did not become ready.
echo Try these commands manually:
echo   ollama list
echo   ollama serve
exit /b 1


:ollama_health
REM Primary Windows readiness check: this verifies both the CLI and local Ollama API.
ollama list >nul 2>&1
if not errorlevel 1 exit /b 0

REM HTTP fallback. Use 127.0.0.1 instead of localhost to avoid IPv4/IPv6 resolution issues.
where curl.exe >nul 2>&1
if not errorlevel 1 (
  curl.exe --silent --fail --max-time 2 http://127.0.0.1:11434/api/tags >nul 2>&1
  if not errorlevel 1 exit /b 0
)

REM Final fallback for Windows systems where curl.exe is unavailable.
powershell -NoProfile -ExecutionPolicy Bypass -Command "try { $r = Invoke-WebRequest -UseBasicParsing 'http://127.0.0.1:11434/api/tags' -TimeoutSec 2; if ($r.StatusCode -eq 200) { exit 0 } else { exit 1 } } catch { exit 1 }" >nul 2>&1
if not errorlevel 1 exit /b 0

exit /b 1


:ensure_ollama_model
set "MODEL_NAME=%~1"
ollama list | findstr /I /C:"%MODEL_NAME%" >nul 2>&1
if not errorlevel 1 (
  echo [OK] Ollama model available: %MODEL_NAME%
  exit /b 0
)

echo [INFO] Ollama model is missing: %MODEL_NAME%
echo [INFO] Downloading model with: ollama pull %MODEL_NAME%
ollama pull "%MODEL_NAME%"
if errorlevel 1 (
  echo [ERROR] Failed to download Ollama model: %MODEL_NAME%
  exit /b 1
)

echo [OK] Ollama model installed: %MODEL_NAME%
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
  echo [OK] Docker Engine is already running.
  exit /b 0
)

set "DOCKER_DESKTOP=%ProgramFiles%\Docker\Docker\Docker Desktop.exe"
if not exist "%DOCKER_DESKTOP%" set "DOCKER_DESKTOP=%LocalAppData%\Docker\Docker Desktop.exe"

if not exist "%DOCKER_DESKTOP%" (
  echo [ERROR] Docker is installed, but Docker Desktop.exe was not found.
  echo Start Docker Desktop manually, then run this script again.
  exit /b 1
)

echo [INFO] Docker Engine is not responding. Starting Docker Desktop...
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

echo [ERROR] Docker Engine did not become ready.
echo Open Docker Desktop and check its status, then run this script again.
exit /b 1


:startup_failed
echo.
echo ==============================================
echo Startup stopped because a required service failed.
echo Fix the error above and run scripts\run-all.bat again.
echo ==============================================
pause
exit /b 1
