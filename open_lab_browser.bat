@echo off
cd /d "%~dp0"
set "EDGE=%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"
if not exist "%EDGE%" set "EDGE=%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"
if not exist "%EDGE%" (
  echo Microsoft Edge could not be found.
  pause
  exit /b 1
)
set "TARGET=%~1"
if not defined TARGET set /p TARGET=Enter an authorized lab URL (Enter for local dashboard): 
if not defined TARGET set "TARGET=http://127.0.0.1:5055"
start "VAPT isolated lab browser" "%EDGE%" --user-data-dir="%~dp0proxy-browser-profile-8899" --proxy-server="http://127.0.0.1:8899" --proxy-bypass-list="<-loopback>" --no-first-run "%TARGET%"
