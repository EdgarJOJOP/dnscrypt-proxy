@echo off
title dnscrypt-proxy

set EXE_PATH=%~dp0main.exe
set TASK_NAME=dnscrypt-proxy

:menu
cls
echo ========================================
echo   dnscrypt-proxy manager
echo ========================================
echo   [1] Install   auto start
echo   [2] Remove    auto start
echo   [3] Restart   service
echo   [4] Status
echo   [Q] Quit
echo ========================================

choice /c 1234Q /n /m "select: "
set n=%errorlevel%

if %n%==1 goto install
if %n%==2 goto uninstall
if %n%==3 goto restart
if %n%==4 goto status
if %n%==5 exit

:install
echo.
if not exist "%EXE_PATH%" (
    echo [ERROR] main.exe not found, build first
    pause
    goto menu
)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v dnscrypt-proxy /t REG_SZ /d "%EXE_PATH%" /f >nul
echo [OK] Auto start installed (registry)
goto start

:uninstall
echo.
taskkill /f /im main.exe >nul 2>&1
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v dnscrypt-proxy /f >nul 2>&1
echo [OK] Auto start removed
pause
goto menu

:restart
echo.
taskkill /f /im main.exe >nul 2>&1
timeout /t 3 >nul
goto start

:start
echo.
if not exist "%EXE_PATH%" (
    echo [ERROR] main.exe not found
    pause
    goto menu
)
start "" "%EXE_PATH%"
echo [OK] main.exe started
pause
goto menu

:stop
echo.
taskkill /f /im main.exe >nul 2>&1
timeout /t 2 >nul
echo [OK] Service stopped
pause
goto menu

:status
echo.
tasklist /fi "imagename eq main.exe" 2>nul | find /i "main.exe" >nul && (
    echo [RUNNING] main.exe is running
) || (
    echo [STOPPED] main.exe is not running
)
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v dnscrypt-proxy >nul 2>&1 && (
    echo [TASK] Auto start is installed
) || (
    echo [TASK] No auto start task
)
pause
goto menu
