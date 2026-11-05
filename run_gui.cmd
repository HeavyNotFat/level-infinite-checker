@echo off
setlocal
cd /d "%~dp0"

where pyw >nul 2>nul
if not errorlevel 1 (
    start "" pyw -3 "%~dp0vcheck_gui.py"
    exit /b 0
)

where pythonw >nul 2>nul
if not errorlevel 1 (
    start "" pythonw "%~dp0vcheck_gui.py"
    exit /b 0
)

where python >nul 2>nul
if not errorlevel 1 (
    start "" python "%~dp0vcheck_gui.py"
    exit /b 0
)

echo Python was not found. Install Python 3.9+ or run: python vcheck_gui.py
pause
exit /b 1
