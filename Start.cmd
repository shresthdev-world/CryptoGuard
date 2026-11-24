@echo off
setlocal
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" detector.py --gui
    if errorlevel 1 goto fail
    exit /b 0
)
where py >nul 2>nul
if errorlevel 1 goto plain
py -3 -c "import tkinter,sys; sys.exit(sys.version_info < (3,11))" >nul 2>nul
if errorlevel 1 goto plain
py -3 detector.py --gui
if errorlevel 1 goto fail
exit /b 0
:plain
python -c "import tkinter,sys; sys.exit(sys.version_info < (3,11))" >nul 2>nul
if errorlevel 1 goto missing
python detector.py --gui
if errorlevel 1 goto fail
exit /b 0
:missing
echo Install Python 3.11 or newer for Windows with Tcl/Tk and IDLE, then try again.
:fail
pause
exit /b 1
