@echo off
setlocal EnableDelayedExpansion

:: Check for administrative privileges and request if necessary
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Set UAC = CreateObject^("Shell.Application"^) : UAC.ShellExecute "cmd.exe", "/c ""%~s0"" %*", "", "runas", 1 > "%temp%\getadmin.vbs"
    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /B
)

:: Set execution policy and download PowerShell script
powershell -Command "Set-ExecutionPolicy Bypass -Scope Process -Force; `
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; `
    Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/valthrunner/valth/main/loader.ps1' -OutFile '%temp%\loader.ps1'"

:: Execute PowerShell script with passed arguments
powershell -ExecutionPolicy Bypass -File "%temp%\loader.ps1" %*
exit /b
