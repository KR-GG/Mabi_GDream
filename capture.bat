@echo off
setlocal EnableDelayedExpansion

:: Fix working directory to the script's location
cd /d "%~dp0"

:: 1. Check for admin privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Admin privileges required. Relaunching with elevation...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

:: 2. Check firewall rule for port 8000
set RULE_NAME=Allow_TCP_8000_GDream
netsh advfirewall firewall show rule name="%RULE_NAME%" | findstr "Enabled" >nul
if %errorlevel% neq 0 (
    echo [INFO] No firewall rule found. Adding rule to allow TCP port 8000...
    netsh advfirewall firewall add rule name="%RULE_NAME%" ^
        dir=in action=allow protocol=TCP localport=8000 profile=any
) else (
    echo [INFO] Firewall rule for TCP port 8000 already exists.
)

:: 3. Start hidden background ping task (to maintain ARP entry)
:: This pings 192.168.219.108 every 60s, silently
start "" /min cmd /c ^
    "for /L %%i in (1,0,2) do (ping -n 2 192.168.219.108 >nul & timeout /t 60 >nul)"

:: 4. Set file paths
set VENV_DIR=gdream
set PYTHON_FILE=.\source\capture.py

:: 5. Create virtual environment if missing
if not exist %VENV_DIR% (
    echo [INFO] Creating virtual environment...
    python -m venv %VENV_DIR%
)

:: 6. Activate virtual environment
call %VENV_DIR%\Scripts\activate.bat

:: 7. Install dependencies
pip install --disable-pip-version-check --quiet websockets scapy brotli

:: 8. Run Python WebSocket server
python %PYTHON_FILE%

endlocal
pause
