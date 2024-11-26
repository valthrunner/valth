@echo off
setlocal EnableDelayedExpansion

:: Check for administrative privileges and request if necessary
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Set UAC = CreateObject^("Shell.Application"^) : UAC.ShellExecute "cmd.exe", "/k cd ""%~sdp0"" && ""%~s0"" %*", "", "runas", 1 > "%temp%\getadmin.vbs"
    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /B
)

:: Define script directory (directory where run.bat is located)
set "SCRIPT_DIR=%~dp0"

:: Change to the script directory
cd /d "%SCRIPT_DIR%"

:: Determine the argument to pass
set "ARG=%~1"
if "%ARG%"=="" set "ARG=run"

:: Create a temp folder within the script directory
set "TEMP_DIR=%SCRIPT_DIR%temp"
if not exist "%TEMP_DIR%" (
    mkdir "%TEMP_DIR%"
)

:: Set execution policy and download PowerShell script to the script directory
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "Set-ExecutionPolicy Bypass -Scope Process -Force; ^
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; ^
    Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/valthrunner/valth/main/loader.ps1' -OutFile '%SCRIPT_DIR%loader.ps1'"

:: Execute PowerShell script with the appropriate argument
powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%loader.ps1" "%ARG%"

exit /b
