@echo off
setlocal EnableDelayedExpansion

:: 1. 관리자 권한 체크
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] 관리자 권한이 필요합니다. 재실행 중...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

:: 2. 방화벽 규칙 확인
set RULE_NAME=Allow TCP 8000
netsh advfirewall firewall show rule name="%RULE_NAME%" | findstr "활성화" >nul
if %errorlevel% neq 0 (
    echo [INFO] 방화벽 규칙이 없습니다. 8000 포트 허용 중...
    netsh advfirewall firewall add rule name="%RULE_NAME%" dir=in action=allow protocol=TCP localport=8000
) else (
    echo [INFO] 8000 포트 방화벽 규칙 이미 존재.
)

:: 3. 파일 경로 설정
set VENV_DIR=gdream
set PYTHON_FILE=.\source\capture.py
set HTML_FILE=stats.html
set CHROME_PATH="C:\Program Files\Google\Chrome\Application\chrome.exe"

:: 4. 가상환경 생성
if not exist %VENV_DIR% (
    echo Creating virtual environment...
    python -m venv %VENV_DIR%
)

:: 5. 가상환경 활성화
call %VENV_DIR%\Scripts\activate.bat

:: 6. 의존성 설치
pip install --disable-pip-version-check --quiet websockets scapy brotli

:: 7. HTML 열기
start "" %CHROME_PATH% "%CD%\%HTML_FILE%"

:: 8. Python 실행
python %PYTHON_FILE%

endlocal
pause
