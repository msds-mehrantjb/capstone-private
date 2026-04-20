@echo off
set "ROOT_DIR=%~dp0.."
pushd "%ROOT_DIR%" || exit /b 1

echo ===============================
echo Starting Capstone System
echo ===============================

REM Activate venv
call conda deactivate
call venv\Scripts\activate

@echo off
echo ===============================
echo Checking Environment...
echo ===============================

REM -------------------------------
REM Check Python version (must be 3.11)
REM -------------------------------
echo Checking Python version...
for /f "tokens=2 delims= " %%i in ('python --version') do set PYVER=%%i

echo Detected Python version: %PYVER%

echo %PYVER% | findstr "3.11" >nul
if errorlevel 1 (
    echo [ERROR] Python 3.11 is NOT active!
    echo Please activate correct venv or install Python 3.11.
    pause
    exit /b
) else (
    echo [OK] Python 3.11 detected
)

REM -------------------------------
REM Check venv exists
REM -------------------------------
if not exist venv\Scripts\activate (
    echo [ERROR] Virtual environment not found!
    echo Run setup_project.bat first.
    pause
    exit /b
) else (
    echo [OK] venv exists
)

REM -------------------------------
REM Activate venv
REM -------------------------------
echo Activating virtual environment...
call venv\Scripts\activate

REM -------------------------------
REM Check .env file
REM -------------------------------
if not exist app\.env (
    echo [ERROR] .env file NOT found!
    echo Create file: app\.env
    pause
    exit /b
) else (
    echo [OK] .env file exists
)

REM -------------------------------
REM Check Node.js
REM -------------------------------
echo Checking Node.js...
node -v >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Node.js is NOT installed!
    pause
    exit /b
) else (
    echo [OK] Node.js detected
)

REM -------------------------------
REM Check npm
REM -------------------------------
npm -v >nul 2>&1
if errorlevel 1 (
    echo [ERROR] npm is NOT installed!
    pause
    exit /b
) else (
    echo [OK] npm detected
)

echo ===============================
echo Environment is READY!
echo ===============================

popd
pause
