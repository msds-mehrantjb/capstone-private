@echo off
set "ROOT_DIR=%~dp0.."

echo Starting Full System...

start "Capstone Backend" /D "%ROOT_DIR%" cmd /k "call venv\Scripts\activate && python -m uvicorn app.main:app --reload"
start "Capstone Frontend" /D "%ROOT_DIR%" cmd /k "call venv\Scripts\activate && cd app && npm run dev"

echo Backend and Frontend started in separate windows.
pause
