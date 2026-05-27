@echo off
REM Spencer Dashboard Launcher - Windows
title Spencer Security Audit Tool

echo.
echo ===============================================
echo   Spencer Web Security Audit Tool v2.0
echo   Starting Dashboard...
echo ===============================================
echo.

REM Check if venv exists
if not exist "venv\Scripts\activate.bat" (
    echo [!] Virtual environment not found.
    echo [!] Run setup first: python -m venv venv ^&^& venv\Scripts\activate ^&^& pip install -r requirements.txt
    pause
    exit /b 1
)

REM Check Node modules
if not exist "dashboard\node_modules" (
    echo [!] Installing Node.js dependencies...
    cd dashboard
    call npm install
    cd ..
)

REM Start the dashboard
echo [*] Starting dashboard on http://localhost:3000
echo [*] Press Ctrl+C to stop
echo.

cd dashboard
node server.js
