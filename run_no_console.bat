@echo off
:: Khởi chạy LAN Printer Manager ở chế độ chạy nền không hiển thị cửa sổ dòng lệnh (cmd)
cd /d "%~dp0"
set "PYTHONPATH=%~dp0src;%PYTHONPATH%"
start "" pythonw -m lan_manager.main

