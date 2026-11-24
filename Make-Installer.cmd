@echo off
setlocal
cd /d "%~dp0"
title CryptoGuard - Make Windows Installer
echo.
echo ===============================================
echo    CryptoGuard Setup.exe Builder
 echo ===============================================
echo.
if not exist "dist\CryptoGuard\CryptoGuard.exe" (
  echo ERROR: dist\CryptoGuard\CryptoGuard.exe not found.
  echo Build your app first using Build-Windows-App.cmd.
  goto :fail
)
if not exist "dist\CryptoGuard\_internal" (
  echo ERROR: _internal folder not found beside CryptoGuard.exe.
  echo Your executable needs all of its PyInstaller files.
  goto :fail
)
set "ISCC="
if exist "%ProgramFiles%\Inno Setup 7\ISCC.exe" set "ISCC=%ProgramFiles%\Inno Setup 7\ISCC.exe"
if not defined ISCC if exist "%ProgramFiles(x86)%\Inno Setup 7\ISCC.exe" set "ISCC=%ProgramFiles(x86)%\Inno Setup 7\ISCC.exe"
if not defined ISCC if exist "%ProgramFiles%\Inno Setup 6\ISCC.exe" set "ISCC=%ProgramFiles%\Inno Setup 6\ISCC.exe"
if not defined ISCC if exist "%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe" set "ISCC=%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
if not defined ISCC (
  for /f "delims=" %%I in ('where ISCC.exe 2^>nul') do if not defined ISCC set "ISCC=%%I"
)
if not defined ISCC (
  echo ERROR: Inno Setup compiler not found.
  echo Install Inno Setup 7 from https://jrsoftware.org/inno-setup/downloads
  echo Then double-click this script again.
  goto :fail
)
echo Using: "%ISCC%"
echo Packaging the UPDATED executable from dist\CryptoGuard\ ...
"%ISCC%" "CryptoGuard.iss"
if errorlevel 1 goto :fail
if not exist "installer\CryptoGuard-Setup-1.0.1.exe" goto :fail
echo.
echo SUCCESS: installer\CryptoGuard-Setup-1.0.1.exe
 echo The installer contains your existing updated CryptoGuard.exe.
echo.
pause
exit /b 0
:fail
echo.
echo INSTALLER NOT BUILT. See the message above.
pause
exit /b 1
