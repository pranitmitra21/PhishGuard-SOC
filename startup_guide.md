# PhishGuard SOC — Full Startup Process

This document describes how to start every service in the project, both for **production (Docker)** and **local development**.

---

## Prerequisites

Make sure these are installed before starting:

| Tool | Minimum Version | Check With |
|---|---|---|
| Docker Desktop | 4.x+ | `docker --version` |
| Node.js | 18+ | `node --version` |
| Python | 3.10+ | `python --version` |
| npm | 9+ | `npm --version` |
| Google Chrome | Any | — |

---

## ⚡ Quickstart — Use the BAT File

Double-click **`START_ALL.bat`** in the project root.

- Choose **`[1] Docker Mode`** for a clean, single-command production startup.
- Choose **`[2] Dev Mode`** to run each service in its own terminal with hot-reload.

---

## Option A: Docker Mode (Recommended for demos)

This starts **all 4 services** (Postgres, Redis, Backend, Frontend) in Docker containers.

```bat
cd d:\phishing_detection
docker-compose up -d
```

| Service | URL |
|---|---|
| Frontend Dashboard | http://localhost |
| Backend API | http://localhost:8000 |
| API Docs (Swagger) | http://localhost:8000/docs |

### Full clean rebuild (if something is broken)
```bat
docker-compose down --volumes --remove-orphans
docker-compose build --no-cache
docker-compose up -d
```

---

## Option B: Dev Mode (For active development)

Run each service manually in separate terminals for hot-reload.

### Step 1 — Start Database & Redis (via Docker)
```bat
docker-compose up -d db redis
```

### Step 2 — Start Hardhat Blockchain Node
```bat
cd d:\phishing_detection\blockchain
npx hardhat node
```
> Leave this terminal open. The local chain runs at `http://localhost:8545`.

### Step 3 — Deploy Smart Contract
Open a **new terminal**:
```bat
cd d:\phishing_detection\blockchain
npx hardhat run scripts/deploy.js --network localhost
```
> Copy the printed contract address into `backend/.env` as `CONTRACT_ADDRESS=0x...`

### Step 4 — Start FastAPI Backend
Open a **new terminal**:
```bat
cd d:\phishing_detection\backend
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```
> API is live at `http://localhost:8000`

### Step 5 — Start React Frontend
Open a **new terminal**:
```bat
cd d:\phishing_detection\frontend
npm install --legacy-peer-deps
npm run dev
```
> Dashboard is live at `http://localhost:5173`

---

## Step 6 — Load the Chrome Extension (All Modes)

> [!IMPORTANT]
> The extension must be loaded manually in Chrome. You only need to do this **once** (or after changes).

1. Open **Google Chrome** and navigate to `chrome://extensions/`
2. Enable **Developer Mode** (top-right toggle)
3. Click **Load unpacked**
4. Select the folder: `d:\phishing_detection\extension`
5. The PhishGuard icon appears in your toolbar — click it to test!

> After any code changes to the extension, click the **reload** button on its card in `chrome://extensions/`.

---

## Environment Variables

The backend reads from `backend/.env`. Key variables:

| Variable | Description | Example |
|---|---|---|
| `DATABASE_URL` | Postgres connection string (auto-set in Docker) | `postgresql://admin:admin123@localhost:5432/phishing_logs` |
| `REDIS_URL` | Redis connection string (auto-set in Docker) | `redis://localhost:6379/0` |
| `WEB3_PROVIDER_URI` | Hardhat/Polygon RPC endpoint | `http://127.0.0.1:8545` |
| `CONTRACT_ADDRESS` | Deployed smart contract address | `0x5FbDB2315678afecb367f032d93F642f64180aa3` |
| `GOOGLE_SAFE_BROWSING_API_KEY` | Google Safe Browsing API key | Get from Google Cloud Console |

---

## Stopping Everything

### Docker Mode
```bat
docker-compose down
```

### Dev Mode
Close each terminal window, then:
```bat
docker-compose down
```

---

## Port Reference

| Port | Service |
|---|---|
| `80` | Frontend (Docker) |
| `5173` | Frontend (Dev) |
| `8000` | FastAPI Backend |
| `8545` | Hardhat Blockchain Node |
| `5432` | PostgreSQL |
| `6379` | Redis |
