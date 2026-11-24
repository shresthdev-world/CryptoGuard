@echo off
setlocal
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" detector.py --gui --demo
    if errorlevel 1 pause
    exit /b
)
where py >nul 2>nul
if not errorlevel 1 (
    py -3 detector.py --gui --demo
) else (
    python detector.py --gui --demo
)
if errorlevel 1 pause
