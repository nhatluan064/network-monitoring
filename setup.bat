@echo off
setlocal EnableDelayedExpansion

REM ==========================================
REM CONFIGURATION
REM ==========================================
set "SERVER_IP=10.10.85.3"
set "SERVER_PORT=5000"
REM ==========================================

echo [INFO] Starting Setup...

REM 1. Check Python
python --version >nul 2>&1
if %errorlevel% equ 0 goto :HAS_PYTHON

echo [WARN] Installing Python...
curl -o python_installer.exe https://www.python.org/ftp/python/3.12.0/python-3.12.0-amd64.exe
python_installer.exe /quiet InstallAllUsers=1 PrependPath=1 Include_test=0
del python_installer.exe
set "PATH=%PATH%;C:\Program Files\Python312\Scripts;C:\Program Files\Python312"

:HAS_PYTHON
echo [INFO] Python Ready.

REM 2. Check Npcap
if exist "%ProgramFiles%\Npcap" goto :HAS_NPCAP
if exist "%ProgramFiles(x86)%\Npcap" goto :HAS_NPCAP

echo [WARN] Installing Npcap...
curl -o npcap_installer.exe https://npcap.com/dist/npcap-1.79.exe
REM Free version does not support silent install (/S). User must click Install.
npcap_installer.exe /winpcap_mode=yes
del npcap_installer.exe

:HAS_NPCAP
echo [INFO] Npcap Ready.

REM 3. Install Libs
echo [INFO] Installing Libraries...
pip install scapy requests python-socketio[client] eventlet flask flask-socketio --disable-pip-version-check

REM 4. Config
echo [INFO] Creating Config...
(
echo {
echo   "server_url": "http://%SERVER_IP%:%SERVER_PORT%"
echo }
) > config.json

REM 5. Auto-Start
echo [INFO] Setting up Auto-Start...
set "STARTUP=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
set "DIR=%~dp0"
if "%DIR:~-1%"=="\" set "DIR=%DIR:~0,-1%"

(
echo @echo off
echo cd /d "%DIR%"
echo start "" /B pythonw agent.py
) > "%DIR%\run_agent.bat"

(
echo @echo off
echo call "%DIR%\run_agent.bat"
) > "%STARTUP%\start_monitor.bat"

echo.
echo [SUCCESS] Setup Complete!
echo [INFO] Starting Agent...
call "%DIR%\run_agent.bat"

pause
