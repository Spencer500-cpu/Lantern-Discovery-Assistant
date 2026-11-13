@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (
  py app.py
) else (
  where python >nul 2>nul
  if %errorlevel%==0 (
    python app.py
  ) else (
    echo Python was not found. Install Python 3, close this window, and try again.
    echo During installation, select "Add Python to PATH".
    pause
  )
)
endlocal
