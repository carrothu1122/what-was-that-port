@echo off
setlocal

set ROOT=%~dp0..\..
set DIST=%ROOT%\dist\windows
set WORK=%ROOT%\build\pyinstaller-windows

if not exist "%DIST%" mkdir "%DIST%"
if not exist "%WORK%" mkdir "%WORK%"

python -m PyInstaller --clean --noconfirm --distpath "%DIST%" --workpath "%WORK%" "%~dp0what-was-that-port-worker.spec"
if errorlevel 1 exit /b %errorlevel%

python -m PyInstaller --clean --noconfirm --distpath "%DIST%" --workpath "%WORK%" "%~dp0what-was-that-port-gui.spec"
if errorlevel 1 exit /b %errorlevel%

echo Built Windows executables in %DIST%
