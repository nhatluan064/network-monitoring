@echo off
echo ========================================
echo Network Monitor Agent - UNINSTALL
echo ========================================
echo.

REM 1. Stop running agent
echo [1/4] Stopping agent...
taskkill /F /IM pythonw.exe 2>nul
timeout /t 2 /nobreak >nul

REM 2. Remove from Startup
echo [2/4] Removing from Startup...
set "STARTUP=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
del "%STARTUP%\start_monitor.bat" 2>nul

REM 3. Delete agent files
echo [3/4] Deleting agent files...
set "DIR=%~dp0"
if "%DIR:~-1%"=="\" set "DIR=%DIR:~0,-1%"

del "%DIR%\agent.py" 2>nul
del "%DIR%\config.json" 2>nul
del "%DIR%\suspicious_keywords.json" 2>nul
del "%DIR%\agent_debug.log" 2>nul
del "%DIR%\run_agent.bat" 2>nul

REM 4. Optional: Uninstall Python packages
echo [4/4] Do you want to uninstall Python packages? (scapy, socketio, etc.)
echo This may affect other programs using these packages.
choice /C YN /M "Uninstall packages"
if %errorlevel%==1 (
    pip uninstall -y scapy python-socketio eventlet pillow
    echo Packages uninstalled.
) else (
    echo Skipped package uninstall.
)

echo.
echo ========================================
echo UNINSTALL COMPLETE!
echo ========================================
echo The agent has been removed from this computer.
echo.
pause
