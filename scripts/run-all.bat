@echo off
setlocal EnableExtensions

set "ROOT_DIR=%~dp0.."
for %%I in ("%ROOT_DIR%") do set "ROOT_DIR=%%~fI"

set "VENV_PYTHON=%ROOT_DIR%\venv\Scripts\python.exe"
set "OLLAMA_MODEL=qwen3:14b"
set "OLLAMA_EMBED_MODEL=nomic-embed-text"

cls
echo ==============================================
echo Capstone Full System Startup
echo ==============================================
echo Project root: %ROOT_DIR%
echo.

echo [1/8] Checking Python 3.11 and backend environment...
call :ensure_backend
if errorlevel 1 goto :startup_failed

echo.
echo [2/8] Checking Node.js and npm...
call :ensure_node
if errorlevel 1 goto :startup_failed

echo.
echo [3/8] Checking frontend dependencies...
call :ensure_frontend
if errorlevel 1 goto :startup_failed

echo.
echo [4/8] Checking Ollama...
call :ensure_ollama
if errorlevel 1 goto :startup_failed

echo.
echo [5/8] Checking required Ollama models...
call :ensure_ollama_model "%OLLAMA_MODEL%"
if errorlevel 1 goto :startup_failed
call :ensure_ollama_model "%OLLAMA_EMBED_MODEL%"
if errorlevel 1 goto :startup_failed

echo.
echo [6/8] Checking Docker Desktop / Docker Engine...
call :ensure_docker
if errorlevel 1 goto :startup_failed

echo.
echo [7/8] Closing existing Capstone dev servers on ports 8002 and 5174...
for %%P in (8002 5174) do (
  for /f "tokens=5" %%A in ('netstat -ano ^| findstr /R /C:":%%P .*LISTENING"') do (
    echo Stopping process %%A on port %%P
    taskkill /PID %%A /F >nul 2>&1
  )
)

echo.
echo [8/8] Starting backend and frontend in separate windows...
start "Capstone Backend" /D "%ROOT_DIR%" cmd /k ""%VENV_PYTHON%" -m uvicorn app.main:app --reload --port 8002"
start "Capstone Frontend" /D "%ROOT_DIR%\app" cmd /k "npm run dev -- --host localhost --port 5174"

echo.
echo ==============================================
echo Capstone startup completed
echo ==============================================
echo Ollama:   http://127.0.0.1:11434
echo Backend:  http://localhost:8002
echo API Docs: http://localhost:8002/docs
echo Frontend: http://localhost:5174
echo Docker Engine: running
echo.
echo Note: Docker Desktop is started automatically when needed.
echo       The data\docker_lab containers are NOT automatically created or started.
echo.
pause
exit /b 0


:ensure_backend
set "PY_BOOTSTRAP="

if exist "%VENV_PYTHON%" (
  echo [OK] Python virtual environment exists.
  goto :backend_dependencies
)

echo [INFO] Project virtual environment is missing. Looking for Python 3.11...
py -3.11 -c "import sys; raise SystemExit(0 if sys.version_info[:2] == (3, 11) else 1)" >nul 2>&1
if not errorlevel 1 set "PY_BOOTSTRAP=py -3.11"

if not defined PY_BOOTSTRAP (
  python -c "import sys; raise SystemExit(0 if sys.version_info[:2] == (3, 11) else 1)" >nul 2>&1
  if not errorlevel 1 set "PY_BOOTSTRAP=python"
)

if not defined PY_BOOTSTRAP (
  echo [ERROR] Python 3.11 was not found.
  echo Install Python 3.11, make sure the Python launcher is available, and run this script again.
  echo Suggested Windows command:
  echo   winget install -e --id Python.Python.3.11
  exit /b 1
)

echo [INFO] Creating project virtual environment at %ROOT_DIR%\venv ...
call %PY_BOOTSTRAP% -m venv "%ROOT_DIR%\venv"
if errorlevel 1 (
  echo [ERROR] Failed to create the Python virtual environment.
  exit /b 1
)

if not exist "%VENV_PYTHON%" (
  echo [ERROR] Virtual environment was created but python.exe was not found.
  exit /b 1
)

:backend_dependencies
"%VENV_PYTHON%" -c "import fastapi, uvicorn, dotenv, pandas, sklearn, chromadb, sentence_transformers, langgraph, langchain_community, ollama, winrm" >nul 2>&1
if not errorlevel 1 (
  echo [OK] Backend Python dependencies are installed.
  goto :ensure_env_file
)

echo [INFO] Installing/updating backend dependencies from requirements.txt ...
"%VENV_PYTHON%" -m pip install --upgrade pip
if errorlevel 1 (
  echo [ERROR] Failed to upgrade pip.
  exit /b 1
)

"%VENV_PYTHON%" -m pip install -r "%ROOT_DIR%\requirements.txt"
if errorlevel 1 (
  echo [ERROR] Failed to install Python dependencies.
  exit /b 1
)

echo [OK] Backend dependencies installed.

:ensure_env_file
if exist "%ROOT_DIR%\app\.env" (
  echo [OK] app\.env exists.
  exit /b 0
)

echo [INFO] app\.env is missing. Creating local Ollama defaults...
> "%ROOT_DIR%\app\.env" (
  echo OLLAMA_URL=http://127.0.0.1:11434/api/generate
  echo OLLAMA_MODEL=%OLLAMA_MODEL%
  echo OLLAMA_EMBED_URL=http://127.0.0.1:11434/api/embeddings
  echo OLLAMA_EMBED_MODEL=%OLLAMA_EMBED_MODEL%
)
if errorlevel 1 (
  echo [ERROR] Failed to create app\.env.
  exit /b 1
)
echo [OK] Created app\.env.
exit /b 0


:ensure_node
call :add_common_node_paths

where node.exe >nul 2>&1
if errorlevel 1 goto :node_missing
where npm.cmd >nul 2>&1
if errorlevel 1 goto :node_missing

for /f "delims=" %%V in ('node --version') do echo [OK] Node.js %%V
for /f "delims=" %%V in ('npm --version') do echo [OK] npm %%V
exit /b 0

:node_missing
echo [WARN] Node.js/npm is not installed or is not available in PATH.
where winget.exe >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Windows Package Manager ^(winget^) was not found.
  echo Install the current Node.js LTS release, then reopen the terminal and run this script again.
  exit /b 1
)

echo This application requires Node.js and npm for the React/Vite frontend.
choice /C YN /N /M "Install Node.js LTS now using winget? [Y/N]: "
if errorlevel 2 (
  echo [ERROR] Node.js installation was skipped. Startup cannot continue without npm.
  exit /b 1
)

echo [INFO] Installing Node.js LTS...
winget install -e --id OpenJS.NodeJS.LTS --accept-source-agreements --accept-package-agreements
if errorlevel 1 (
  echo [ERROR] Node.js installation failed.
  echo Install Node.js LTS manually, then run this script again.
  exit /b 1
)

call :add_common_node_paths
where node.exe >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Node.js was installed, but node.exe is not visible to this process yet.
  echo Close this window, open a new PowerShell/Command Prompt, and run scripts\run-all.bat again.
  exit /b 1
)
where npm.cmd >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Node.js was installed, but npm.cmd is not visible to this process yet.
  echo Close this window, open a new PowerShell/Command Prompt, and run scripts\run-all.bat again.
  exit /b 1
)

for /f "delims=" %%V in ('node --version') do echo [OK] Node.js %%V
for /f "delims=" %%V in ('npm --version') do echo [OK] npm %%V
exit /b 0


:add_common_node_paths
if defined NVM_SYMLINK if exist "%NVM_SYMLINK%\node.exe" set "PATH=%NVM_SYMLINK%;%PATH%"
if exist "%ProgramFiles%\nodejs\node.exe" set "PATH=%ProgramFiles%\nodejs;%PATH%"
if exist "%ProgramFiles(x86)%\nodejs\node.exe" set "PATH=%ProgramFiles(x86)%\nodejs;%PATH%"
if exist "%LOCALAPPDATA%\Programs\nodejs\node.exe" set "PATH=%LOCALAPPDATA%\Programs\nodejs;%PATH%"
exit /b 0


:ensure_frontend
if not exist "%ROOT_DIR%\app\package.json" (
  echo [ERROR] app\package.json was not found.
  exit /b 1
)

if exist "%ROOT_DIR%\app\node_modules\.bin\vite.cmd" (
  echo [OK] Frontend node_modules exists.
  exit /b 0
)

echo [INFO] Frontend dependencies are missing. Running npm install...
pushd "%ROOT_DIR%\app" || exit /b 1
call npm install
if errorlevel 1 (
  popd
  echo [ERROR] npm install failed.
  exit /b 1
)
popd
echo [OK] Frontend dependencies installed.
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
ollama list >nul 2>&1
if not errorlevel 1 exit /b 0

where curl.exe >nul 2>&1
if not errorlevel 1 (
  curl.exe --silent --fail --max-time 2 http://127.0.0.1:11434/api/tags >nul 2>&1
  if not errorlevel 1 exit /b 0
)

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
echo Startup stopped because a required component failed.
echo Fix the error above and run scripts\run-all.bat again.
echo ==============================================
pause
exit /b 1
