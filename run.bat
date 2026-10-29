@echo off
setlocal
chcp 65001 >nul
title LAN Printer Manager - He thong Quan tri May in va Mang LAN

echo ====================================================================
echo        LAN PRINTER MANAGER - HE THONG QUAN TRI MAY IN LAN
echo ====================================================================
echo.

:: Di chuyển tới thư mục gốc chứa file .bat
cd /d "%~dp0"

:: Đặt biến môi trường PYTHONPATH
set "PYTHONPATH=%~dp0src;%PYTHONPATH%"

:: Kiểm tra lệnh Python
where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [LOI] Khong tim thay Python trong PATH he thong!
    echo Vui long cai dat Python 3.12+ va chon "Add python.exe to PATH".
    echo.
    pause
    exit /b 1
)

:: Kiểm tra file .env
if not exist ".env" (
    echo [THONG BAO] Dang tao file .env tu .env.example...
    if exist ".env.example" (
        copy /y ".env.example" ".env" >nul
        echo Da tao file .env mac dinh.
    )
)

echo [*] Dang khoi chay ung dung LAN Printer Manager...
echo.

:: Chạy ứng dụng qua module entrypoint
python -m lan_manager.main

:: Nếu ứng dụng thoát với mã lỗi
if %errorlevel% neq 0 (
    echo.
    echo ====================================================================
    echo [LOI] Ung dung da thoat voi ma loi: %errorlevel%
    echo Vui long kiem tra file nhat ky tai logs\app.log
    echo ====================================================================
    pause
)

endlocal
