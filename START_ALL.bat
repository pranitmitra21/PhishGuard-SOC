@echo off
title PhishGuard SOC - Startup Manager
color 0A

echo.
echo  =====================================================
echo   PHISHGUARD SOC v2.0 - FULL STACK STARTUP
echo   Multi-Layer AI + Blockchain Threat Detection
echo  =====================================================

:: -------------------------------------------------------
:: MODE SELECTION
:: -------------------------------------------------------
echo  Choose startup mode:
echo.
echo   [1] DOCKER MODE    ^(full production stack - recommended^)
echo   [2] DEV MODE       ^(separate terminals for each service^)
echo.
set /p MODE="  Enter choice (1 or 2): "

if "%MODE%"=="1" goto DOCKER_MODE
if "%MODE%"=="2" goto DEV_MODE
echo  Invalid choice. Exiting.
pause
exit /b 1


:: ======================================================
:: DOCKER MODE
:: ======================================================
:DOCKER_MODE
echo.
echo  [DOCKER] Checking Docker Desktop is running...
docker info >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Docker is not running! Please start Docker Desktop first.
    pause
    exit /b 1
)
echo  [OK] Docker is running.
echo.

echo  [DOCKER] Stopping any existing containers...
docker-compose down >nul 2>&1

echo  [DOCKER] Starting all services (db, redis, backend, frontend)...
docker-compose up --build -d

if errorlevel 1 (
    echo.
    echo  [ERROR] Docker Compose failed. Run: docker-compose logs
    pause
    exit /b 1
)

echo.
echo  =====================================================
echo   ALL SERVICES ARE UP!
echo  =====================================================
echo.
echo   Dashboard    : http://localhost
echo   Backend API  : http://localhost:8000
echo   API Docs     : http://localhost:8000/docs
echo   DB (Postgres): localhost:5432
echo   Redis        : localhost:6379
echo.
echo  [INFO] To load the Chrome extension:
echo    1. Open chrome://extensions/
echo    2. Enable Developer Mode
echo    3. Click "Load unpacked" and select the /extension folder
echo.
echo  Press any key to open the dashboard in your browser...
pause >nul
start http://localhost
goto END


:: ======================================================
:: DEV MODE
:: ======================================================
:DEV_MODE
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

echo  [DEV] Starting Hardhat blockchain node in a new window...
start "Hardhat Node" cmd /k "cd /d %~dp0blockchain && npx hardhat node"
echo  [WAIT] Giving blockchain node 8 seconds to initialize...
timeout /t 8 /nobreak >nul
echo  [OK] Hardhat node should be running at http://localhost:8545
echo.

echo  [DEV] Deploying ThreatLog smart contract...
echo  !! IMPORTANT: When deployment finishes, copy the contract address !!
echo  !! and paste it into backend\.env as CONTRACT_ADDRESS=0x...       !!
echo.
start "Contract Deploy - READ THE ADDRESS" cmd /k "cd /d %~dp0blockchain && npx hardhat run scripts/deploy.js --network localhost && echo. && echo ====== COPY THE ADDRESS ABOVE INTO backend\.env ====== && pause"
timeout /t 10 /nobreak >nul

echo  [DEV] Starting Blockchain Event Watcher (live threat feed)...
start "Blockchain Event Watcher" cmd /k "cd /d %~dp0blockchain && npx hardhat run scripts/watch_events.js --network localhost"
timeout /t 3 /nobreak >nul

echo  [DEV] Starting FastAPI backend (Random Forest AI Engine)...
start "FastAPI Backend - AI Engine" cmd /k "cd /d %~dp0backend && pip install -r requirements.txt -q && uvicorn main:app --host 0.0.0.0 --port 8000 --reload"
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
echo   Blockchain Node    : http://localhost:8545
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

:END
echo.
echo  [PhishGuard SOC v2.0] All systems online.
echo  [AI Engine] Random Forest + Heuristics + Visual AI active.
echo  [Blockchain] Immutable threat ledger armed.
echo.
pause
