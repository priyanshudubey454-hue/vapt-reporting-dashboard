@echo off
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Python environment is not set up yet.
  echo Follow the setup steps in README.md first.
  pause
  exit /b 1
)
".venv\Scripts\python.exe" app.py
pause
