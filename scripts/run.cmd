@echo off
rem run.cmd [Configuration]   - launches APIMonitor.exe from bin\<Configuration>\.
rem        Configuration defaults to Debug. Manifest already requires admin, UAC will prompt.

setlocal
set "SCRIPT_DIR=%~dp0"
set "CFG=%~1"
if "%CFG%"=="" set "CFG=Release"

set "EXE=%SCRIPT_DIR%..\bin\%CFG%\APIMonitor.exe"

if not exist "%EXE%" (
    echo Not found: %EXE%
    echo Build solution in %CFG% ^| x64 first.
    exit /b 1
)

echo Starting %EXE%
start "" "%EXE%"
endlocal
