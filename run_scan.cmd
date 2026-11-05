@echo off
setlocal
cd /d "%~dp0"

set "PY=py -3"
where py >nul 2>nul
if errorlevel 1 set "PY=python"

%PY% vcheck.py %*
set "RC=%ERRORLEVEL%"

if "%VCHECK_PAUSE%"=="1" pause
exit /b %RC%
