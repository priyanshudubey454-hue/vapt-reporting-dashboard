@echo off
cd /d "%~dp0"
where mitmdump >nul 2>&1
if errorlevel 1 (
  echo mitmproxy is not installed or mitmdump is not on PATH.
  echo Install mitmproxy using its official Windows installer, then reopen this file.
  echo https://mitmproxy.org/downloads/
  pause
  exit /b 1
)
echo Local proxy listening on 127.0.0.1:8899. Keep this window open.
echo Only private IPs or localhost listed in the dashboard scope are forwarded.
mitmdump --listen-host 127.0.0.1 --listen-port 8899 --set confdir="%~dp0proxy-config" --set connection_strategy=lazy -s proxy_addon.py
pause
