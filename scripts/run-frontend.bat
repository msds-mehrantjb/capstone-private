@echo off
set "ROOT_DIR=%~dp0.."
pushd "%ROOT_DIR%" || exit /b 1

echo Starting Frontend...

REM Activate venv (optional but consistent)
call venv\Scripts\activate

REM Run frontend
cd app
npm run dev

popd
pause
