@echo off
setlocal EnableExtensions

set "ROOT_DIR=%~dp0.."
for %%I in ("%ROOT_DIR%") do set "ROOT_DIR=%%~fI"
set "VENV_PYTHON=%ROOT_DIR%\venv\Scripts\python.exe"

cls
echo ===============================
echo Checking Capstone Environment
echo ===============================
echo Project root: %ROOT_DIR%
echo.

if not exist "%ROOT_DIR%\venv\Scripts\activate" (
  echo [ERROR] Virtual environment not found at venv\Scripts\activate
  echo Run scripts\setup-project.bat first.
  goto :failed
)
echo [OK] venv exists

if not exist "%VENV_PYTHON%" (
  echo [ERROR] Python executable not found at %VENV_PYTHON%
  goto :failed
)

for /f "tokens=2 delims= " %%I in ('"%VENV_PYTHON%" --version') do set "PYVER=%%I"
echo Detected Python version: %PYVER%
echo %PYVER% | findstr /B "3.11" >nul
if errorlevel 1 (
  echo [ERROR] Python 3.11 is required.
  goto :failed
)
echo [OK] Python 3.11 detected

if not exist "%ROOT_DIR%\app\.env" (
  echo [ERROR] app\.env was not found.
  echo Create %ROOT_DIR%\app\.env or run scripts\run-all.bat to generate defaults.
  goto :failed
)
echo [OK] app\.env exists

call :add_common_node_paths
where node.exe >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Node.js is not available in PATH.
  goto :failed
)
for /f "delims=" %%I in ('node --version') do echo [OK] Node.js %%I

where npm.cmd >nul 2>&1
if errorlevel 1 (
  echo [ERROR] npm is not available in PATH.
  goto :failed
)
for /f "delims=" %%I in ('npm --version') do echo [OK] npm %%I

echo.
echo ===============================
echo Environment is READY!
echo ===============================
pause
exit /b 0

:add_common_node_paths
if defined NVM_SYMLINK if exist "%NVM_SYMLINK%\node.exe" set "PATH=%NVM_SYMLINK%;%PATH%"
if exist "%ProgramFiles%\nodejs\node.exe" set "PATH=%ProgramFiles%\nodejs;%PATH%"
if exist "%ProgramFiles(x86)%\nodejs\node.exe" set "PATH=%ProgramFiles(x86)%\nodejs;%PATH%"
if exist "%LOCALAPPDATA%\Programs\nodejs\node.exe" set "PATH=%LOCALAPPDATA%\Programs\nodejs;%PATH%"
exit /b 0

:failed
echo.
echo ===============================
echo Environment check failed.
echo ===============================
pause
exit /b 1
