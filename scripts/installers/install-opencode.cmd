@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File "%~dp0install-opencode.ps1" %*
exit /b %ERRORLEVEL%
