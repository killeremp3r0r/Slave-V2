@echo off
setlocal
set "APP_DIR=%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$python = (Get-Command python -ErrorAction Stop).Source; Start-Process -FilePath $python -ArgumentList 'slave.py' -WorkingDirectory '%APP_DIR%' -Verb RunAs"
