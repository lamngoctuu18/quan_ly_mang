@echo off
:: Khoi chay LAN Printer Manager khong hien thi cua so CMD
cd /d "%~dp0"
set "PYTHONPATH=%~dp0src;%PYTHONPATH%"
start "" pythonw -m lan_manager.main
