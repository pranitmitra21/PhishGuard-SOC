# 🛡️ PhishGuard: Decentralized AI Phishing Detection

![PhishGuard System](https://img.shields.io/badge/Security-Level_9-ff003c.svg?style=for-the-badge) ![Ethereum Sepolia](https://img.shields.io/badge/Blockchain-Ethereum_Sepolia-blue.svg?style=for-the-badge) ![AI Powered](https://img.shields.io/badge/AI-XGBoost_%2B_MLP-39ff14.svg?style=for-the-badge)

**PhishGuard** is a full-stack, enterprise-grade Threat Intelligence platform. It combines a real-time Chrome Extension, a high-performance Neural Network ensemble, and an immutable Ethereum Smart Contract architecture to detect, quarantine, and permanently log phishing threats on a decentralized ledger.

## 🧠 System Architecture

The platform operates across four primary layers:

### 1. The Interceptor (Chrome Extension)
A highly optimized, latency-critical Chrome Extension that acts as the front-line hardware authentication key and web traffic analyzer.
*   **Auto-Scanning**: Silently analyzes DOM structures, SSL certificates, and URL parameters in <300ms.
*   **Zero-Trust Overlays**: Injects immediate Amber (Warning) or Pink (Critical Threat) blocking overlays to protect the user before network execution finishes.
*   **Hardware Auth**: Authenticates analysts into the SOC dashboard securely via encoded JWT injection.

### 2. The Brain (FastAPI AI Engine)
A Python-based AI inference server built for extreme concurrency.
*   **Neural Ensemble**: Utilizes a combination of an XGBoost Classifier and a Multi-Layer Perceptron (MLP) trained on over 50,000+ verified phishing vectors to achieve 96.7% accuracy.
*   **Heuristics Engine**: Parallelizes network I/O to simultaneously query Google Safe Browsing APIs, WHOIS records, SSL certs, and Tranco Top 1M whitelists.
*   **Postgres State**: Manages Role-Based Access Control (RBAC) and local telemetry data.

### 3. The SOC (React + Vite Dashboard)
A cinematic, cyber-aesthetic Security Operations Center (SOC).
*   **Role-Based Access**: Renders different matrix visualizations based on JWT credentials (User, Analyst, Admin).
*   **Threat Matrix**: Displays real-time intercepted threats, their exact heuristic triggers, and their decentralized verification status.

### 4. The Ledger (Ethereum Smart Contracts)
An immutable, decentralized ledger deployed on the **Ethereum Sepolia Testnet** (`0xe5aF0d720dBC87feA55cd0A4688Ca930dB406D5f`).
*   **Immutable Evidence**: When a threat is confirmed, the system pins the detailed report to an IPFS node (producing a CID) and pushes a compact JSON summary directly onto the blockchain.
*   **Cryptographic Verification**: Analysts can verify the origin and authenticity of any logged threat by querying the Etherscan block explorer.

---

## 🚀 Quick Start Guide

### Prerequisites
*   Node.js (v18+)
*   Python (3.10+)
*   PostgreSQL
*   A Web3 Wallet with Sepolia ETH

### 1. Database & Environment Setup
Clone the repository and configure your environment variables:
```bash
git clone https://github.com/pranitmitra21/phishing_detection.git
cd phishing_detection
```
Create a `.env` in `backend/` and `blockchain/` containing your `PRIVATE_KEY` and `WEB3_PROVIDER_URI`.

### 2. Launch the System
For local deployment, use the master initialization script:
```bash
# Windows
.\START_ALL.bat
```
This script will concurrently spawn the Uvicorn AI Server, the React Dashboard, and initialize database connections.

### 3. Install the Extension
1. Open Google Chrome and navigate to `chrome://extensions/`
2. Enable **Developer Mode** in the top right.
3. Click **Load unpacked** and select the `/extension` directory.

---

## 🔒 Security & Verification
To verify the integrity of intercepted threats, cross-reference the URL hashes on the official [Sepolia Etherscan Block Explorer](https://sepolia.etherscan.io/address/0xe5aF0d720dBC87feA55cd0A4688Ca930dB406D5f#internaltx). The blockchain never forgets.
