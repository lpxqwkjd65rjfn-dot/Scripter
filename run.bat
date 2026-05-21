@echo off
setlocal
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    echo [setup] Creating venv...
    python -m venv .venv || goto :error
    .venv\Scripts\python.exe -m pip install --upgrade pip || goto :error
    .venv\Scripts\python.exe -m pip install -r requirements.txt || goto :error
)

if not exist "config.yaml" (
    echo [setup] config.yaml not found, copying from config.example.yaml
    copy /Y config.example.yaml config.yaml >nul
    echo [setup] Please edit config.yaml with your credentials and run again.
    pause
    exit /b 0
)

.venv\Scripts\python.exe -m rkn_probe %*
exit /b %errorlevel%

:error
echo [error] Setup failed.
pause
exit /b 1
