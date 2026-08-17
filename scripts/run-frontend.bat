@echo off
setlocal EnableExtensions

set "ROOT_DIR=%~dp0.."
for %%I in ("%ROOT_DIR%") do set "ROOT_DIR=%%~fI"

if not defined CAPSTONE_FRONTEND_PORT set "CAPSTONE_FRONTEND_PORT=5174"
if not defined CAPSTONE_API_BASE_URL (
  if not defined CAPSTONE_API_HOST set "CAPSTONE_API_HOST=127.0.0.1"
  if not defined CAPSTONE_API_PORT set "CAPSTONE_API_PORT=8003"
  set "CAPSTONE_API_BASE_URL=http://%CAPSTONE_API_HOST%:%CAPSTONE_API_PORT%"
)

pushd "%ROOT_DIR%\app" || exit /b 1

echo Starting Frontend on http://localhost:%CAPSTONE_FRONTEND_PORT% ...
echo Using API base URL: %CAPSTONE_API_BASE_URL%

set "VITE_API_BASE_URL=%CAPSTONE_API_BASE_URL%"
npm run dev -- --host localhost --port %CAPSTONE_FRONTEND_PORT%

popd
pause
