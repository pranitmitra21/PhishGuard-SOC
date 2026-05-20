# 🚀 Ultimate PhishGuard Deployment Guide

This guide will walk you through deploying your entire PhishGuard platform to the internet for free using modern cloud providers. 

---

## Phase 1: Deploying the AI Backend (Render)

Render is the easiest platform for hosting Python APIs and PostgreSQL databases.

### 1. Database Setup
1. Go to [Render.com](https://render.com) and sign up with GitHub.
2. Click **New +** -> **PostgreSQL**.
3. Name it `phishguard-db` and select the Free tier.
4. Click **Create Database**.
5. Once created, copy the **Internal Database URL** (e.g., `postgres://user:pass@host/db`).

### 2. FastAPI Backend Setup
1. On Render, click **New +** -> **Web Service**.
2. Connect your GitHub account and select the `phishing_detection` repository.
3. Scroll down and set the **Root Directory** to `backend`.
4. Set the **Build Command** to: 
   ```bash
   pip install -r requirements.txt
   ```
5. Set the **Start Command** to: 
   ```bash
   uvicorn main:app --host 0.0.0.0 --port $PORT
   ```
6. Scroll down to **Environment Variables** and add all the keys from your local `backend/.env`:
   * `DATABASE_URL`: (Paste the *Internal Database URL* you copied in Step 1)
   * `WEB3_PROVIDER_URI`: `https://ethereum-sepolia-rpc.publicnode.com`
   * `PRIVATE_KEY`: `cd011516441c023a7e7c5d5e2070c104e2d454df993a5492f3d87822a92787c3`
   * `CONTRACT_ADDRESS`: `0xe5aF0d720dBC87feA55cd0A4688Ca930dB406D5f`
   * `GOOGLE_SAFE_BROWSING_API_KEY`: (Your Google API Key)
7. Click **Create Web Service**. 
8. Once it finishes building, Render will give you a public URL (e.g., `https://phishguard-backend.onrender.com`). **Copy this URL.**

---

## Phase 2: Deploying the Dashboard (Vercel)

Vercel is the absolute best platform for hosting React/Vite frontends.

1. Go to [Vercel.com](https://vercel.com) and sign up with GitHub.
2. Click **Add New** -> **Project**.
3. Import your `phishing_detection` repository.
4. In the configuration settings, look for **Root Directory**. Click Edit, and select the `frontend` folder.
5. Vercel automatically detects Vite, so leave the Build and Output settings as default.
6. (Optional) If you have a `.env` in your frontend, add those variables here.
7. Click **Deploy**.
8. Within 2 minutes, Vercel will give you a live URL (e.g., `https://phishguard-dashboard.vercel.app`).

---

## Phase 3: Packaging the Chrome Extension

Now that your backend has a real internet URL, we must point the Chrome extension to it and upload it to Google.

### 1. Update the Code
1. Open `extension/background.js` and `extension/popup.js` in your code editor.
2. Find the line that says:
   ```javascript
   const BACKEND_URL = "http://127.0.0.1:8000";
   ```
3. Change it to your new Render Backend URL:
   ```javascript
   const BACKEND_URL = "https://phishguard-backend.onrender.com";
   ```

### 2. Zip the Extension
1. Open your File Explorer and go into the `extension` folder.
2. Select **all** the files inside it (manifest.json, popup.html, content.js, background.js, etc.).
3. Right-click -> **Compress to ZIP file**. Name it `PhishGuard_V2.zip`.

### 3. Publish to Chrome Web Store
1. Go to the [Chrome Web Store Developer Dashboard](https://chrome.google.com/webstore/devconsole/).
2. You will need to pay a one-time $5 developer fee if you haven't already.
3. Click **Add New Item**.
4. Upload your `PhishGuard_V2.zip` file.
5. Fill out the Store Listing (Description, Upload your `UPGRADES.png` as screenshots).
6. Under Privacy, declare that you only request the minimum permissions (`activeTab`, `storage`).
7. Click **Submit for Review**.

---

## Phase 4: Final Verification
1. Try logging into your Vercel dashboard URL.
2. The dashboard will now communicate with your Render backend, which talks to your Render Postgres database.
3. When the Chrome Extension is downloaded by a user, it will intercept bad websites, ping your Render backend, and instantly write the threat to your Sepolia smart contract!

**Congratulations! Your platform is fully live.**
