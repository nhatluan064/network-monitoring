@echo off
echo ========================================
echo Network Monitor Agent - COMPLETE UNINSTALL
echo ========================================
echo.

REM 1. Kill agent process if running
echo [1/7] Stopping agent process...
taskkill /F /IM python.exe 2>nul
taskkill /F /IM pythonw.exe 2>nul
timeout /t 2 /nobreak >nul

REM 2. Remove from Startup (Registry)
echo [2/7] Removing from Windows Startup...
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "NetworkMonitorAgent" /f 2>nul

REM 3. Delete agent files
echo [3/7] Deleting agent files...
if exist "%~dp0agent.py" del /f /q "%~dp0agent.py"
if exist "%~dp0config.json" del /f /q "%~dp0config.json"
if exist "%~dp0suspicious_keywords.json" del /f /q "%~dp0suspicious_keywords.json"
if exist "%~dp0agent_debug.log" del /f /q "%~dp0agent_debug.log"
if exist "%~dp0run_agent.bat" del /f /q "%~dp0run_agent.bat"
if exist "%~dp0temp_screen_*" del /f /q "%~dp0temp_screen_*"

REM 4. Uninstall Npcap (CRITICAL - This causes ERP/Printing issues!)
echo [4/7] Uninstalling Npcap driver...
echo This is CRITICAL to fix ERP/MES/Printing lag!
if exist "%ProgramFiles%\Npcap\Uninstall.exe" (
    echo Found Npcap, uninstalling...
    "%ProgramFiles%\Npcap\Uninstall.exe" /S
    timeout /t 3 /nobreak >nul
)
if exist "%ProgramFiles(x86)%\Npcap\Uninstall.exe" (
    "%ProgramFiles(x86)%\Npcap\Uninstall.exe" /S
    timeout /t 3 /nobreak >nul
)

REM 5. Remove Python packages (optional)
echo [5/7] Uninstalling Python packages...
pip uninstall -y scapy python-socketio pillow 2>nul

REM 6. Clear DNS cache
echo [6/7] Flushing DNS cache...
ipconfig /flushdns >nul

REM 7. Reset Network Adapters
echo [7/7] Resetting network adapters...
ipconfig /release >nul 2>&1
ipconfig /renew >nul 2>&1

echo.
echo ========================================
echo UNINSTALL COMPLETE!
echo ========================================
echo.
echo IMPORTANT NEXT STEPS:
echo 1. RESTART your computer to fully remove Npcap driver
echo 2. After restart, test ERP/MES/Printing
echo 3. If still slow, manually uninstall Npcap from Control Panel
echo.
pause
