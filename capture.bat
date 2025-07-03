@echo off
setlocal

set VENV_DIR=gdream
set PYTHON_FILE=./source/capture.py
set HTML_FILE=stats.html
set CHROME_PATH="C:\Program Files\Google\Chrome\Application\chrome.exe"

if not exist %VENV_DIR% (
    echo Creating virtual environment...
    python -m venv %VENV_DIR%
)

call %VENV_DIR%\Scripts\activate.bat

pip install --disable-pip-version-check --quiet websockets scapy brotli

start "" %CHROME_PATH% "%CD%\%HTML_FILE%"

python %PYTHON_FILE%

endlocal
pause