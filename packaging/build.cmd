@echo off
setlocal
cd /d "%~dp0.."

python -m PyInstaller --noconfirm --clean VirusChecker.spec
if errorlevel 1 (
    echo Build failed.
    exit /b 1
)

echo.
echo Built: %CD%\dist\VirusChecker.exe
exit /b 0
