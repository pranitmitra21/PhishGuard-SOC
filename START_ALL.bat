@echo off
title PhishGuard SOC - Startup Manager
color 0A

echo.
echo  =====================================================
echo   PHISHGUARD SOC v2.0 - FULL STACK STARTUP
echo   Multi-Layer AI + Blockchain Threat Detection
echo  =====================================================


echo.
echo  [DEV] Checking Docker Desktop is running (for DB + Redis)...
docker info >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Docker is not running! Please start Docker Desktop first.
    pause
    exit /b 1
)
echo  [OK] Docker is running.
echo.

echo  [DEV] Starting Postgres + Redis via Docker...
docker-compose up -d db redis
timeout /t 5 /nobreak >nul
echo  [OK] Database and Redis are up.
echo.

echo  [DEV] Connected to Polygon Amoy Testnet!
echo  [OK] Smart Contract is permanently deployed at: 0xB13cEba4Ff578cDDA49e1490e71c39918175Afe2
echo.

echo  [DEV] Starting FastAPI backend (Random Forest AI Engine)...
start "FastAPI Backend - AI Engine" cmd /k "cd /d %~dp0backend && pip install -r requirements.txt -q && python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload"
timeout /t 6 /nobreak >nul

echo  [DEV] Starting React SOC Dashboard (frontend)...
start "React SOC Dashboard" cmd /k "cd /d %~dp0frontend && npm install --legacy-peer-deps && npm run dev"
timeout /t 4 /nobreak >nul

echo.
echo  =====================================================
echo   ALL PHISHGUARD SERVICES LAUNCHING!
echo  =====================================================
echo.
echo   SOC Dashboard      : http://localhost:5173
echo   Backend API        : http://localhost:8000
echo   API Docs (Swagger) : http://localhost:8000/docs
echo   Blockchain Node    : Polygon Amoy Testnet
echo   DB (Postgres)      : localhost:5432
echo   Redis Cache        : localhost:6379
echo.
echo  -------------------------------------------------------
echo  [CHROME EXTENSION SETUP]
echo    1. Open chrome://extensions
echo    2. Enable Developer Mode (top right toggle)
echo    3. Click Load unpacked
echo    4. Select the 'extension' folder in this project
echo  -------------------------------------------------------
echo.
echo  [DEMO CHECKLIST]
echo    - Check backend terminal shows: 'Uvicorn running on 0.0.0.0:8000'
echo    - Check CONTRACT_ADDRESS is set in backend\.env
echo    - Check Blockchain Watcher window is listening for events
echo    - Open any website in Chrome to trigger auto-scan
echo.
echo  Press any key to open the SOC Dashboard in your browser...
pause >nul
start http://localhost:5173


echo.
echo  [PhishGuard SOC v2.0] All systems online.
echo  [AI Engine] Random Forest + Heuristics + Visual AI active.
echo  [Blockchain] Immutable threat ledger armed.
echo.
pause
