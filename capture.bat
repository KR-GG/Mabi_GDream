@echo off
setlocal EnableDelayedExpansion

:: 1. Check for admin privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Admin privileges required. Relaunching with elevation...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

:: 2. Check firewall rule for port 8000
set RULE_NAME=Allow_TCP_8000
netsh advfirewall firewall show rule name="%RULE_NAME%" | findstr "Enabled" >nul
if %errorlevel% neq 0 (
    echo [INFO] No firewall rule found. Adding rule to allow TCP port 8000...
    netsh advfirewall firewall add rule name="%RULE_NAME%" dir=in action=allow protocol=TCP localport=8000
) else (
    echo [INFO] Firewall rule for TCP port 8000 already exists.
)

:: 3. Set file paths
set VENV_DIR=gdream
set PYTHON_FILE=.\source\capture.py
set HTML_FILE=stats.html
set CHROME_PATH="C:\Program Files\Google\Chrome\Application\chrome.exe"

:: 4. Create virtual environment if missing
if not exist %VENV_DIR% (
    echo [INFO] Creating virtual environment...
    python -m venv %VENV_DIR%
)

:: 5. Activate virtual environment
call %VENV_DIR%\Scripts\activate.bat

:: 6. Install dependencies
pip install --disable-pip-version-check --quiet websockets scapy brotli

:: 7. Launch HTML in Chrome
start "" %CHROME_PATH% "%CD%\%HTML_FILE%"

:: 8. Run Python WebSocket server
python %PYTHON_FILE%

endlocal
pause
