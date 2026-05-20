# PhishGuard SOC — Project Introduction

## Overview

**PhishGuard SOC** is a full-stack, industry-grade
cybersecurity platform designed to detect, analyze, and log phishing
URLs in real time. Built as a B.Tech capstone project, it goes far
beyond a standard student submission — integrating Machine Learning,
Computer Vision, Blockchain immutability, Threat Intelligence APIs, and
a Security Operations Center (SOC) dashboard into one cohesive
system.

The project name stands for **Phishing Guard – Security
Operations Center**, and it functions like a real enterprise
threat detection gateway that a company’s security team would use to
monitor and respond to web-based attacks.

---

## Project Goals

1. **Detect phishing URLs** before users can be harmed —
   in real time, directly in the browser.
2. **Provide explainability** — tell the user *why*
   a site was flagged (not just a score).
3. **Create an immutable audit trail** of all confirmed
   phishing threats on a blockchain.
4. **Continuously improve** through an automated MLOps
   retraining pipeline fed by user reports.
5. **Present threat data** to security analysts via a
   professional SOC dashboard.

---

## System Architecture

The system is composed of **5 major components** working
together:

```
┌─────────────────────────────────────────────────────────────────┐
│                        PhishGuard SOC                          │
│                                                                  │
│  ┌───────────────┐     ┌──────────────┐     ┌──────────────┐   │
│  │ Chrome        │────▶│ FastAPI      │────▶│ PostgreSQL   │   │
│  │ Extension     │     │ Backend      │     │ Database     │   │
│  │ (Manifest V3) │◀────│ (Python)     │     │              │   │
│  └───────────────┘     └──────┬───────┘     └──────────────┘   │
│                               │                                  │
│                    ┌──────────┼──────────────────┐              │
│                    ▼          ▼                   ▼              │
│            ┌──────────┐ ┌──────────┐      ┌──────────────┐     │
│            │ ML Engine│ │ Redis    │      │ Blockchain   │     │
│            │(Random   │ │ Cache    │      │ (Ethereum Sepolia Testnet/    │     │
│            │ Forest)  │ │          │      │  Solidity)   │     │
│            └──────────┘ └──────────┘      └──────────────┘     │
│                                                                  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │           React SOC Dashboard (Vite + TailwindCSS)        │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Component Breakdown

### 1. 🧩 Chrome Extension (`/extension`)

The entry point for all URL scanning. Built using the
**Manifest V3** standard.

* **`content.js`** — Injected into every
  webpage. Extracts rich DOM features:
  + URL length, presence of `@` symbol, subdomain count,
    HTTPS status
  + **Deep DOM Analysis**: Detects if password forms submit
    to a cross-origin domain (“Zero-Click Theft”)
  + Detects hidden/invisible `<iframe>` elements
    (classic phishing trick)
  + Counts password input fields
* **`background.js`** — Service worker that
  receives extracted features and sends them to the backend API.
* **`popup.js` / `popup.html`** — A
  full UI inside the extension popup showing the scan result, confidence
  score, and AI-generated reasons.
* **`content.js` (Overlay Injector)** — When a
  site is confirmed as Phishing, injects a **full-screen
  cyberpunk-styled red warning** that blocks the page with
  explainable AI reasons listed clearly.

---

### 2. ⚙️ FastAPI Backend (`/backend`)

The core processing engine. A high-performance Python REST API
running on **FastAPI + Uvicorn**.

#### Detection Pipeline (`/detect` endpoint)

URL scanning follows a **5-tier waterfall decision
system**:

| Tier | Check | Description |
| --- | --- | --- |
| **1** | Tranco Whitelist | O(1) in-memory set lookup — top 1 million legitimate domains. Instant `Safe` verdict. |
| **2** | WHOIS Domain Age | Queries domain registration age. Brand-new domains (<30 days) are high risk; older domains are discounted. |
| **3** | Redis Cache | Previous results are cached for 1 hour — zero inference cost on repeat scans. |
| **3.5** | Google Safe Browsing API | Queries Google’s threat intelligence database before running local ML. If Google flags it, it’s immediately blocked at 100% confidence. |
| **4** | XGBoost + MLP Ensemble ML Model | Local scikit-learn model runs inference to generate a base threat score from 6 URL/DOM features. |
| **4.5** | Lexical Heuristics Engine | Advanced text analysis layer (see below). |
| **5** | Multi-Layer Decision Engine | Combines all scores into a `final_confidence` and assigns a final status of `Safe`, `Suspicious`, or `Phishing`. |

#### Final Verdict Thresholds

* `≥ 80%` confidence → **Phishing** (blocked,
  logged to blockchain)
* `40%–79%` confidence → **Suspicious**
  (warning shown)
* `< 40%` confidence → **Safe**

---

### 3. 🤖 Machine Learning Engine (`/backend/ml`)

The intelligence core of PhishGuard.

#### Model

* **Algorithm**: XGBoost + Multi-Layer Perceptron (MLP) Ensemble
  (scikit-learn)
* **Model file**: `xgboost_mlp_model.pkl` (~12 MB
  trained model)
* **Input Features**: 6 structured features extracted
  from URL and DOM
  1. `url_length` — Phishing URLs tend to be very long
  2. `has_at_symbol` — `@` in a URL can redirect to
     a different host
  3. `num_subdomains` — Excessive subdomains are a red
     flag
  4. `is_https` — Absence of HTTPS on login pages is
     suspicious
  5. `num_redirects` — Multiple redirects indicate
     obfuscation
  6. `suspicious_dom_elements` — Count of dangerous DOM
     patterns
* **Output**: Probability distribution across 3 classes
  (`Safe`, `Suspicious`, `Phishing`).
  These are combined into a **threat score 0–100**.

#### Lexical Heuristics Engine (`heuristics.py`)

A sophisticated rule-based analysis layer that catches URL tricks the
ML model alone can’t see:

| Check | How it Works | Risk Added |
| --- | --- | --- |
| **Shannon Entropy** | Measures randomness of hostname. High randomness = DGA (bot-generated) domain. | +20 points |
| **Typosquatting Detection** | Levenshtein distance algorithm checks if domain is 1-2 characters away from 20 major brands (Google, PayPal, Microsoft, etc.). Also catches character swaps like `0→o`, `1→l`. | +40 points |
| **Brand in Subdomain** | Checks if a major brand name appears in the subdomain (e.g., `paypal.secure-login.xyz`). | +35 points |
| **Suspicious Keywords** | Counts phishing keywords (`login`, `verify`, `secure`, `billing`, `refund`, `gift`, etc.) in the URL. | +10 per keyword |

#### MLOps Retraining Pipeline (`retrain_pipeline.py`)

* User-reported phishing URLs (via `/report` endpoint) are
  stored in the database.
* The `/admin/retrain` endpoint triggers a
  **background retraining job** that:
  1. Fetches all `User_Reported_Phishing` records from the
     database
  2. Appends them to the training CSV as labeled `Phishing`
     samples
  3. Retrains the XGBoost + MLP Ensemble model on the expanded dataset
  4. Hot-reloads the new `xgboost_mlp_model.pkl` into memory with
     **zero downtime**

---

### 4. 👁️ Visual AI / Computer Vision Engine (`vision_engine.py`)

A zero-day phishing detection capability that catches attacks that
bypass URL scanners entirely (e.g., using a legitimate compromised
domain).

* **Triggered by**: Chrome extension capturing a
  screenshot when a password form is detected
* **API Endpoint**: `POST /vision-scan`
  accepts base64-encoded screenshot
* **Algorithm**: **SSIM (Structural Similarity
  Index)** from `scikit-image` + OpenCV
  1. Decodes the base64 screenshot into an OpenCV image matrix
  2. Resizes and converts to grayscale both images
  3. Computes SSIM score (0.0 = completely different, 1.0 = identical)
     against every image in the `/reference_images/`
     directory
  4. If any match exceeds **80% similarity** → the page is a
     UI clone of a known brand
* **Result**: Returns `is_clone`,
  `matched_brand`, and `similarity_score`
* **Purpose**: If a phishing site visually mimics
  “Microsoft Login” but the domain isn’t `microsoft.com`, it’s
  immediately flagged regardless of URL analysis

---

### 5. ⛓️ Blockchain Audit Trail (`/blockchain`)

Confirmed phishing URLs are permanently logged to a local
**Ethereum blockchain** (using Ethereum Sepolia Testnet for development) via
a Solidity smart contract.

#### Smart Contract: `ThreatLog.sol`

```
struct PhishingLog {
    string urlHash;    // SHA256 hash of the URL (privacy-preserving)
    string ipfsHash;   // IPFS CID pointing to full evidence package
    uint256 timestamp;
    address reporter;
}
```

* **`addLog(urlHash, ipfsHash)`** — Records
  the SHA256 URL hash and IPFS evidence link on-chain
* **`isLogged(urlHash)`** — Checks if a URL
  has already been reported (prevents duplicate transactions)
* **IPFS Integration**: Evidence packages (DOM features,
  screenshots) are designed to be pinned to IPFS via Pinata, making the
  audit trail fully decentralized
* **Async by design**: Blockchain logging runs as a
  **FastAPI background task** so the 2–10 second Ethereum
  transaction latency never blocks the user-facing response

> [!IMPORTANT] The blockchain provides **tamper-proof
> immutability** — once a phishing URL is logged, no one (including
> the system admins) can alter or delete that record. This is a key
> enterprise security property.

---

### 6. 🗄️ Data Layer

#### PostgreSQL Database (`/backend/database.py`, `models.py`)

Stores every scan result with full feature vectors: - URL, SHA256
hash, detection status, confidence score - All 6 ML features for audit
and retraining - Blockchain logging status, timestamp

#### Redis Cache

* URL scan results cached for **1 hour** to skip repeat
  inference
* User-reported URLs cached for **24 hours**
* Connection via Docker container (`redis:alpine`)

#### Training Datasets (`/merged_all_rows_dataset`)

The XGBoost + MLP Ensemble model was trained on **~98.5 MB merged
dataset** combining: | Dataset | Size | Description |
|———|——|————-| | `PhiUSIIL_Phishing_URL_Dataset.csv` | ~54 MB
| Academic phishing URL dataset | | `malicious_phish.csv` |
~44 MB | Real-world malicious URL collection | |
`merged_all_rows_dataset.csv` | ~98 MB | Combined,
deduplicated master dataset |

The processed and feature-engineered version is stored as
`processed_features.csv` (~7.7 MB) in the `ml/`
directory.

Additionally, `tranco.txt` (~15 MB) contains the
**Tranco Top 1 Million** legitimate domain whitelist loaded
into memory at startup for O(1) safe-domain verification.

---

### 7. 🖥️ SOC Dashboard Frontend (`/frontend`)

A **React + Vite** application styled with TailwindCSS,
designed to look like a professional Security Operations Center
interface.

* **Real-time Threat Statistics**: Total scans, phishing
  detected, suspicious URLs, safe URLs
* **Detection Log Table**: Scrollable live feed of all
  scanned URLs with status indicators
* **7-Day Security Score Chart**: Line graph showing the
  ratio of safe to total scans per day (using Recharts)
* **Global Search**: Search across all logged URL
  history
* **Model Accuracy Display**: Shows current XGBoost+MLP model
  accuracy and false positive rate
* **Served via Nginx** inside Docker in production

---

## Infrastructure & Deployment

The entire application is **containerized with Docker
Compose**:

| Container | Image | Port | Role |
| --- | --- | --- | --- |
| `phishing_db` | `postgres:15-alpine` | 5432 | Persistent threat log database |
| `phishing_redis` | `redis:alpine` | 6379 | Result cache |
| `phishing_backend` | Custom Python build | 8000 | FastAPI API server |
| `phishing_frontend` | Custom Nginx build | 80 | Static React SOC dashboard |

* **`START_ALL.bat`** — Windows batch script
  that starts the entire stack with one click
* **Health checks** on DB and Redis ensure the backend
  doesn’t start until dependencies are ready
* **`.github/`** — GitHub Actions CI/CD
  workflows configured for automated testing and deployment

---

## Technology Stack Summary

| Layer | Technology |
| --- | --- |
| ML Model | scikit-learn (XGBoost + MLP Ensemble) |
| Computer Vision | OpenCV + scikit-image (SSIM) |
| Heuristics | Custom Python (Shannon Entropy, Levenshtein Distance) |
| Backend API | FastAPI + Uvicorn (Python 3) |
| Threat Intel | Google Safe Browsing API v4 |
| WHOIS | `python-whois` library |
| Blockchain | Solidity + Ethereum Sepolia Testnet + Web3.py |
| Database | PostgreSQL (SQLAlchemy ORM) |
| Cache | Redis |
| Frontend | React + Vite + TailwindCSS + Recharts |
| Browser Extension | Chrome Extension Manifest V3 |
| Deployment | Docker Compose + Nginx |
| Domain Whitelist | Tranco Top 1M (in-memory set) |

---

## Key Differentiating Features

1. **Explainable AI (XAI)**: Every phishing verdict
   comes with human-readable reasons (e.g., *“Typosquatting detected
   (mimicking ‘paypal’)”*, *“Brand name ‘google’ used deceptively in
   subdomain”*). The reasons are displayed both in the extension popup
   and as a full-screen browser overlay.
2. **Multi-Layer Defense**: No single point of failure.
   If Google Safe Browsing is down → ML engine runs. If ML confidence is
   low → heuristics compensate. If the domain is brand-new → WHOIS age
   multiplies risk.
3. **Zero-Day Visual Detection**: Catches phishing
   attacks that hide behind legitimate URLs by comparing page screenshots
   to known brand login pages.
4. **Continuous Learning**: The system gets smarter
   over time — user reports feed directly into the retraining pipeline,
   creating a feedback loop.
5. **Immutable Blockchain Audit**: Confirmed threats
   are permanently recorded on-chain with IPFS evidence, ensuring
   compliance and tamper-proof logging.
6. **Production-Ready Architecture**: Full Docker
   Compose deployment, Redis caching, async background tasks, health
   checks, and Nginx reverse proxy.