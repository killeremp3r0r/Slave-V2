@echo off
setlocal
cd /d "%~dp0"

echo Installing Slave V2 requirements...
python -m pip install -r requirements.txt
if errorlevel 1 (
    echo.
    echo Installation failed. Check the error above and confirm Python and pip are installed.
    pause
    exit /b 1
)

echo.
echo Requirements installed successfully.
pause
