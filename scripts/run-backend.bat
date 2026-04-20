@echo off
set "ROOT_DIR=%~dp0.."
pushd "%ROOT_DIR%" || exit /b 1

echo Starting Backend...

REM Activate venv
call venv\Scripts\activate

REM Run FastAPI
python -m uvicorn app.main:app --reload

popd
pause
