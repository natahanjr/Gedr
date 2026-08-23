@echo off
REM CyberCode Inspector — One-Click Start (Windows)
REM Reads credentials from .env in the project root.

echo.
echo ============================================================
echo   CyberCode Inspector — Starting...
echo ============================================================
echo.

REM Check for Python
where python3 >nul 2>&1
if %errorlevel% neq 0 (
    where python >nul 2>&1
    if %errorlevel% neq 0 (
        echo [ERROR] Python not found. Install Python 3.10+ from python.org
        pause
        exit /b 1
    )
    set PYTHON=python
) else (
    set PYTHON=python3
)

REM Check for venv
if exist ".venv\Scripts\python.exe" (
    set PYTHON=.venv\Scripts\python.exe
) else if exist ".venv\Scripts\python" (
    set PYTHON=.venv\Scripts\python
)

echo [*] Python: %PYTHON%

REM Start AI microservice
echo.
echo [AI] Starting AI microservice on port 8002...
start "CyberCode AI" /B cmd /c "cd /d %~dp0.. && %PYTHON% start_ai.py"

timeout /t 3 /nobreak >nul

REM Start backend
echo [BE] Starting backend on port 8000...
start "CyberCode Backend" /B cmd /c "cd /d %~dp0.. && %PYTHON% main.py"

timeout /t 3 /nobreak >nul

echo.
echo ============================================================
echo   CyberCode Inspector is running!
echo   Dashboard: http://127.0.0.1:8000
echo   Press any key to stop all services...
echo ============================================================

REM Open browser
start http://127.0.0.1:8000

pause

REM Kill services on exit
taskkill /FI "WINDOWTITLE eq CyberCode AI" /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq CyberCode Backend" /F >nul 2>&1
