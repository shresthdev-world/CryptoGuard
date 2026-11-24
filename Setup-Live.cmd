@echo off
setlocal
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" goto deps
where py >nul 2>nul
if errorlevel 1 goto plain
py -3 -c "import tkinter,sys; sys.exit(sys.version_info < (3,11))" >nul 2>nul
if errorlevel 1 goto plain
py -3 -m venv .venv
if errorlevel 1 goto fail
goto deps
:plain
python -c "import tkinter,sys; sys.exit(sys.version_info < (3,11))" >nul 2>nul
if errorlevel 1 goto missing
python -m venv .venv
if errorlevel 1 goto fail
:deps
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 goto fail
".venv\Scripts\python.exe" -c "import psutil, tkinter, sys; sys.exit(sys.version_info < (3,11))"
if errorlevel 1 goto fail
echo Live monitoring is ready. Open Start.cmd.
pause
exit /b 0
:missing
echo Install Python 3.11 or newer with Tcl/Tk, then run setup again.
:fail
echo Setup did not finish. Check the error above.
pause
exit /b 1
