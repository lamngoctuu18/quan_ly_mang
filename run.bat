@echo off
setlocal
title LAN Printer Manager - Quan tri He thong May in LAN

cd /d "%~dp0"
set "PYTHONPATH=%~dp0src;%PYTHONPATH%"

echo ====================================================================
echo        LAN PRINTER MANAGER - HE THONG QUAN TRI MAY IN LAN
echo ====================================================================
echo.
echo [*] Dang khoi dong ung dung, vui long doi giay lat...
echo.

python -m lan_manager.main

if %errorlevel% neq 0 (
    echo.
    echo ====================================================================
    echo [THONG BAO] Ung dung da thoat voi ma loi: %errorlevel%
    echo Vui long kiem tra file log tai: logs\app.log
    echo ====================================================================
    pause
)

endlocal
