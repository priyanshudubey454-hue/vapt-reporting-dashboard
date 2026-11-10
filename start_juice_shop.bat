@echo off
title OWASP Juice Shop - Local VAPT Lab
where docker >nul 2>&1
if errorlevel 1 (
  echo Docker was not found. Install Docker Desktop, start it, then run this file again.
  echo You can also run Juice Shop inside a private VMware lab and use its private IP.
  pause
  exit /b 1
)
echo Starting OWASP Juice Shop bound to this computer only at http://127.0.0.1:3000
echo Leave this window open while practicing. Press Ctrl+C to stop the lab.
docker run --rm --name vapt-juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop
pause
