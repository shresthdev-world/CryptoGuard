@echo off
setlocal
cd /d "%~dp0"
title CryptoGuard Windows Application Builder
echo ----------------------------------------------
echo CryptoGuard - build the native Windows app
 echo ----------------------------------------------
if exist ".build-env\Scripts\python.exe" goto install
where py >nul 2>nul
if not errorlevel 1 (
  py -3 -m venv .build-env
) else (
  python -m venv .build-env
)
if errorlevel 1 goto failed
:install
".build-env\Scripts\python.exe" -m pip install --disable-pip-version-check -r requirements.txt pyinstaller
if errorlevel 1 goto failed
".build-env\Scripts\python.exe" -m PyInstaller --noconfirm --clean CryptoGuard.spec
if errorlevel 1 goto failed
if not exist "dist\CryptoGuard\CryptoGuard.exe" goto failed
echo.
echo SUCCESS: dist\CryptoGuard\CryptoGuard.exe
echo This folder is the runnable application. Keep its _internal files together.
set "ISCC="
if exist "%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe" set "ISCC=%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
if not defined ISCC if exist "%ProgramFiles%\Inno Setup 6\ISCC.exe" set "ISCC=%ProgramFiles%\Inno Setup 6\ISCC.exe"
if defined ISCC (
  echo Found Inno Setup. Building optional installer...
  "%ISCC%" CryptoGuard.iss
  if errorlevel 1 (
    echo Installer failed. Standalone EXE folder was successfully created.
  ) else (
    echo SUCCESS: installer\CryptoGuard-Setup-1.0.0.exe
  )
) else (
  echo Optional installer: install Inno Setup 6, then open CryptoGuard.iss and Compile.
)
echo.
pause
exit /b 0
:failed
echo.
echo BUILD FAILED. Check the error text above. Nothing was installed.
pause
exit /b 1
