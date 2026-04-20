@echo off
set "ROOT_DIR=%~dp0.."
pushd "%ROOT_DIR%" || exit /b 1

echo ===============================
echo Setting up Capstone Project...
echo ===============================

REM Create virtual environment with Python 3.11
py -3.11 -m venv venv

REM Activate venv
call venv\Scripts\activate

REM Upgrade pip
python -m pip install --upgrade pip

REM Install Python dependencies
pip install -r requirements.txt

REM Install frontend dependencies
cd app
npm install
cd ..

echo ===============================
echo Setup completed successfully!
echo ===============================
popd
pause
