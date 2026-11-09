
@echo off
title DeepShield Backend
cd /d "%~dp0"

echo =================================
echo       DEEPSHIELD STARTING
echo =================================

if not exist ".venv\Scripts\python.exe" (
    echo Virtual environment not found!
    pause
    exit /b 1
)

REM Gmail SMTP configuration
set "SMTP_USER=makboy0001@gmail.com"
set "SMTP_APP_PASSWORD=ehmucnsanbghxxln"
set "SMTP_HOST=smtp.gmail.com"
set "SMTP_PORT=465"
set "SMTP_SECURITY=ssl"

echo Starting Flask backend...
".venv\Scripts\python.exe" app.py

pause
