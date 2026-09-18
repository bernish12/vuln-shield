@echo off
title VulnShield - Cyber Forensic & Security Auditor
color 0A
echo ===================================================================
echo           VULNSHIELD - HOST FORENSIC & AUDITING ENGINE
echo ===================================================================
echo.
echo [*] Checking Node.js runtime...
where node >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Node.js is not installed on this system.
    echo Please install Node.js from https://nodejs.org/ to run live host audits.
    pause
    exit /b
)

echo [*] Starting VulnShield local forensic server on port 8000...
start "" http://localhost:8000/index.html#scan-device
node server.js
pause
