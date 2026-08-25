@echo off
setlocal EnableExtensions EnableDelayedExpansion

set "ROOT_DIR=%~dp0.."
for %%I in ("%ROOT_DIR%") do set "ROOT_DIR=%%~fI"

set "VENV_PYTHON=%ROOT_DIR%\venv\Scripts\python.exe"
set "OLLAMA_MODEL=qwen3.8:27b"
set "OLLAMA_EMBED_MODEL=nomic-embed-text"
set "API_HOST=127.0.0.1"
set "PREFERRED_API_PORT=8003"
set "FALLBACK_API_PORT=8002"
set "API_PORT=%PREFERRED_API_PORT%"
set "FRONTEND_PORT=5174"
set "BACKEND_STDOUT=backend_stdout.log"
set "BACKEND_STDERR=backend_stderr.log"
set "FRONTEND_STDOUT=..\frontend_stdout.log"
set "FRONTEND_STDERR=..\frontend_stderr.log"
set "PIP_DISABLE_PIP_VERSION_CHECK=1"
call :set_api_base_url

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
echo [3/8] Synchronizing frontend dependencies...
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
echo [7/8] Closing existing Capstone dev servers on ports %PREFERRED_API_PORT%, %FALLBACK_API_PORT%, and %FRONTEND_PORT%...
for %%P in (%PREFERRED_API_PORT% %FALLBACK_API_PORT% %FRONTEND_PORT%) do (
  for /f "tokens=5" %%A in ('netstat -ano ^| findstr /R /C:":%%P .*LISTENING"') do (
    echo Stopping process %%A on port %%P
    taskkill /PID %%A /F >nul 2>&1
  )
)

echo.
echo [8/8] Starting backend, verifying API, then starting frontend...
call :start_application
if errorlevel 1 goto :startup_failed

echo.
echo ==============================================
echo Capstone startup completed
echo ==============================================
echo Ollama:   http://127.0.0.1:11434
echo Backend:  %API_BASE_URL%
echo API Docs: %API_BASE_URL%/docs
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
"%VENV_PYTHON%" -c "import fastapi, uvicorn, dotenv, pandas, sklearn, langgraph, langchain_community, ollama, winrm" >nul 2>&1
if errorlevel 1 (
  echo [INFO] Core backend dependencies are missing.
  call :ensure_pypi_access
  if errorlevel 1 exit /b 1

  echo [INFO] Installing backend dependencies from requirements.txt ...
  "%VENV_PYTHON%" -m pip install --retries 1 --timeout 15 -r "%ROOT_DIR%\requirements.txt"
  if errorlevel 1 (
    echo [ERROR] Failed to install Python dependencies.
    echo Test PyPI manually with:
    echo   "%VENV_PYTHON%" -m pip install --retries 1 --timeout 15 -r "%ROOT_DIR%\requirements.txt"
    exit /b 1
  )

  echo [OK] Core backend dependencies installed.
) else (
  echo [OK] Core backend Python dependencies are installed.
)

"%VENV_PYTHON%" -c "import chromadb" >nul 2>&1
if errorlevel 1 (
  echo [WARN] Optional package chromadb could not be imported.
  echo        Chroma-backed AI search features may be limited until optional dependencies are repaired.
)

"%VENV_PYTHON%" -c "import sentence_transformers" >nul 2>&1
if errorlevel 1 (
  echo [WARN] Optional package sentence_transformers could not be imported.
  echo        Embedding-based AI features may be limited until Torch/DLL dependencies are repaired.
)

:ensure_env_file
if not exist "%ROOT_DIR%\app\.env" (
  echo [INFO] app\.env is missing. Creating local defaults...
  > "%ROOT_DIR%\app\.env" (
    echo OLLAMA_URL=http://127.0.0.1:11434/api/generate
    echo OLLAMA_MODEL=%OLLAMA_MODEL%
    echo OLLAMA_EMBED_URL=http://127.0.0.1:11434/api/embeddings
    echo OLLAMA_EMBED_MODEL=%OLLAMA_EMBED_MODEL%
    echo VITE_API_BASE_URL=%API_BASE_URL%
  )
  if errorlevel 1 (
    echo [ERROR] Failed to create app\.env.
    exit /b 1
  )
  echo [OK] Created app\.env.
  exit /b 0
)

echo [OK] app\.env exists.
findstr /B /C:"VITE_API_BASE_URL=" "%ROOT_DIR%\app\.env" >nul 2>&1
if errorlevel 1 (
  echo VITE_API_BASE_URL=%API_BASE_URL%>>"%ROOT_DIR%\app\.env"
  echo [OK] Added VITE_API_BASE_URL=%API_BASE_URL% to app\.env.
)
exit /b 0


:set_api_base_url
set "API_BASE_URL=http://%API_HOST%:%API_PORT%"
exit /b 0


:sync_frontend_api_base
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$path = '%ROOT_DIR%\app\.env';" ^
  "$existing = @();" ^
  "if (Test-Path -LiteralPath $path) { $existing = Get-Content -LiteralPath $path }" ^
  "$filtered = @($existing | Where-Object { $_ -notmatch '^VITE_API_BASE_URL=' });" ^
  "$filtered += 'VITE_API_BASE_URL=%API_BASE_URL%';" ^
  "Set-Content -LiteralPath $path -Value $filtered -Encoding UTF8"
if errorlevel 1 (
  echo [WARN] Failed to synchronize VITE_API_BASE_URL in app\.env.
  exit /b 1
)
echo [OK] Synchronized VITE_API_BASE_URL=%API_BASE_URL% in app\.env.
exit /b 0


:ensure_pypi_access
echo [INFO] Checking DNS resolution for pypi.org...
"%VENV_PYTHON%" -c "import socket; socket.getaddrinfo('pypi.org', 443)" >nul 2>&1
if not errorlevel 1 (
  echo [OK] pypi.org resolves.
  goto :check_pypi_https
)

echo [WARN] DNS lookup for pypi.org failed.
echo [INFO] Flushing Windows DNS cache and retrying once...
ipconfig /flushdns >nul 2>&1

timeout /t 2 /nobreak >nul
"%VENV_PYTHON%" -c "import socket; socket.getaddrinfo('pypi.org', 443)" >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Windows still cannot resolve pypi.org.
  echo.
  echo This is a DNS/network problem, not a Python or Capstone problem.
  echo Run these commands in PowerShell to diagnose it:
  echo   Resolve-DnsName pypi.org
  echo   nslookup pypi.org
  echo   Test-NetConnection pypi.org -Port 443
  echo.
  echo Also check VPN, proxy, firewall, DNS filtering, or temporary network outages.
  exit /b 1
)

echo [OK] DNS resolution recovered after flushing the cache.

:check_pypi_https
where curl.exe >nul 2>&1
if errorlevel 1 (
  echo [OK] DNS works. curl.exe is unavailable, so HTTPS preflight is skipped.
  exit /b 0
)

curl.exe --silent --fail --location --max-time 10 https://pypi.org/simple/ >nul 2>&1
if errorlevel 1 (
  echo [ERROR] pypi.org resolves, but HTTPS access to PyPI failed.
  echo Check VPN, proxy, firewall, SSL inspection, or outbound HTTPS filtering.
  echo Test manually with:
  echo   curl.exe -I https://pypi.org/simple/
  exit /b 1
)

echo [OK] PyPI HTTPS access is available.
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

echo [INFO] Running npm install to synchronize package.json and node_modules...
pushd "%ROOT_DIR%\app" || exit /b 1
call npm install --no-audit --no-fund
if errorlevel 1 (
  popd
  echo [ERROR] npm install failed.
  echo Check DNS/network access to the npm registry and run again.
  exit /b 1
)

call npm ls react-markdown remark-gfm rehype-raw --depth=0 >nul 2>&1
if errorlevel 1 (
  popd
  echo [ERROR] Required markdown packages are still missing after npm install.
  echo Expected: react-markdown, remark-gfm, rehype-raw
  exit /b 1
)

popd
echo [OK] Frontend dependencies are synchronized.
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


:start_application
pushd "%ROOT_DIR%" || exit /b 1
"%VENV_PYTHON%" -c "from app.main import app; assert app is not None" >nul 2>&1
if errorlevel 1 (
  popd
  echo [ERROR] Backend import preflight failed.
  echo Run this command to see the Python error:
  echo   "%VENV_PYTHON%" -c "from app.main import app"
  exit /b 1
)
popd

call :try_start_backend %PREFERRED_API_PORT%
if errorlevel 1 (
  echo [WARN] Backend was not healthy on preferred port %PREFERRED_API_PORT%.
  echo [INFO] Retrying backend on fallback port %FALLBACK_API_PORT% ...
  call :try_start_backend %FALLBACK_API_PORT%
  if errorlevel 1 (
    echo [ERROR] Backend did not become healthy on either %PREFERRED_API_PORT% or %FALLBACK_API_PORT%.
    echo Check %BACKEND_STDOUT% and %BACKEND_STDERR% in the project root for details.
    exit /b 1
  )
)

echo [OK] Backend health check passed.
echo [INFO] Starting Vite frontend with VITE_API_BASE_URL=%API_BASE_URL% ...
start "Capstone Frontend" /MIN /D "%ROOT_DIR%\app" cmd /c "set VITE_API_BASE_URL=%API_BASE_URL%&& npm run dev -- --host localhost --port %FRONTEND_PORT% > %FRONTEND_STDOUT% 2> %FRONTEND_STDERR%"
exit /b 0


:try_start_backend
set "API_PORT=%~1"
call :set_api_base_url

if exist "%ROOT_DIR%\%BACKEND_STDOUT%" del /q "%ROOT_DIR%\%BACKEND_STDOUT%" >nul 2>&1
if exist "%ROOT_DIR%\%BACKEND_STDERR%" del /q "%ROOT_DIR%\%BACKEND_STDERR%" >nul 2>&1

echo [INFO] Starting FastAPI backend on %API_BASE_URL% ...
echo [INFO] Uvicorn reload is disabled for Windows startup stability.
start "Capstone Backend" /MIN /D "%ROOT_DIR%" cmd /c ""%VENV_PYTHON%" -m uvicorn app.main:app --host %API_HOST% --port %API_PORT% > %BACKEND_STDOUT% 2> %BACKEND_STDERR%"

echo [INFO] Waiting for backend health endpoint...
for /L %%I in (1,1,30) do (
  call :backend_health
  if not errorlevel 1 (
    call :sync_frontend_api_base
    if errorlevel 1 exit /b 1
    exit /b 0
  )
  timeout /t 2 /nobreak >nul
)

if exist "%ROOT_DIR%\%BACKEND_STDERR%" (
  findstr /C:"error while attempting to bind on address" "%ROOT_DIR%\%BACKEND_STDERR%" >nul 2>&1
  if not errorlevel 1 (
    echo [WARN] Port %API_PORT% could not be bound.
  )
)

exit /b 1


:backend_health
where curl.exe >nul 2>&1
if not errorlevel 1 (
  curl.exe --silent --fail --max-time 2 %API_BASE_URL%/health >nul 2>&1
  if not errorlevel 1 exit /b 0
)

powershell -NoProfile -ExecutionPolicy Bypass -Command "try { $r = Invoke-WebRequest -UseBasicParsing '%API_BASE_URL%/health' -TimeoutSec 2; if ($r.StatusCode -eq 200) { exit 0 } else { exit 1 } } catch { exit 1 }" >nul 2>&1
if not errorlevel 1 exit /b 0
exit /b 1


:startup_failed
echo.
echo ==============================================
echo Startup stopped because a required component failed.
echo Fix the error above and run scripts\run-all.bat again.
echo ==============================================
pause
exit /b 1
