@echo off
echo =======================================================
echo     Starting Phishing Detection System
echo =======================================================

echo.
echo [1/3] Starting Local Blockchain (Hardhat Node)...
start "Blockchain Node" cmd /k "cd blockchain && npx hardhat node"

:: Wait for 5 seconds to ensure the node is fully up and running before deploying
timeout /t 5 /nobreak >nul

echo.
echo Deploying Smart Contract to Local Node...
cd blockchain
call npx hardhat run scripts/deploy.js --network localhost
cd ..

echo.
echo [2/3] Starting FastAPI Backend...
start "FastAPI Backend" cmd /k "cd backend && call venv\Scripts\activate.bat && uvicorn main:app --reload"

echo.
echo [3/3] Starting React Frontend Dashboard...
start "React Dashboard" cmd /k "cd frontend && npm run dev"

echo.
echo =======================================================
echo   All Services have been launched in separate windows!
echo =======================================================
echo.
echo Dashboard URL: http://localhost:5173
echo Backend API : http://127.0.0.1:8000
echo.
echo To use the system:
echo 1. Open Google Chrome.
echo 2. Go to chrome://extensions/
echo 3. Enable "Developer mode" (top right).
echo 4. Click "Load unpacked" and select the "extension" folder located here:
echo    %CD%\extension
echo 5. Pin the extension and try it on any website!
echo.
pause
