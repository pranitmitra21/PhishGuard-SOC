# PhishGuard SOC — Detailed Flow of Work

---

## Overview

PhishGuard SOC operates as a **distributed, event-driven
system** with six distinct workflows that activate in response to
user browser activity, admin commands, or scheduled operations. Each
workflow is self-contained yet interconnected — the output of one flow
often becomes the input trigger of another.

| Workflow | Trigger | Duration |
| --- | --- | --- |
| **URL Detection Pipeline** | User visits any webpage | ~100–800ms |
| **Chrome Extension Lifecycle** | Tab load / popup open | ~50–200ms |
| **Visual AI Pipeline** | Password form detected on page | ~200–500ms |
| **Blockchain Audit Logging** | Phishing verdict confirmed | ~2–10s (async) |
| **MLOps Retraining Pipeline** | Admin triggers `/admin/retrain` | ~30–120s |
| **SOC Dashboard Data Flow** | Analyst opens dashboard | On-demand polling |

---

## Flow 1 — Master System Architecture Flow

This diagram shows how all components of PhishGuard communicate at a
system level.

```
flowchart TD
    A["🌐 User Opens Browser Tab"] --> B["Chrome Extension\nContent Script (content.js)"]
    B --> C["Feature Extractor\n8 DOM + URL signals"]
    C --> D["Background Service Worker\n(background.js)"]
    D -->|"POST /detect"| E["FastAPI Backend\n(main.py)"]

    E --> F{"Tranco\nWhitelist?"}
    F -->|"YES → Safe 100%"| G["Return Safe Response"]
    F -->|"NO → Continue"| H["WHOIS Domain Age\n(whois_utils.py)"]

    H --> I{"Redis Cache\nHit?"}
    I -->|"YES → Cached"| G
    I -->|"NO → Continue"| J["Google Safe Browsing API\n(threat_intel.py)"]

    J -->|"BLOCKED"| K["Phishing @ 100%"]
    J -->|"CLEAR"| L["XGBoost + MLP Ensemble\nML Inference\n(model_inference.py)"]

    L --> M["Lexical Heuristics\nEngine\n(heuristics.py)"]
    M --> N["Multi-Layer\nDecision Engine"]
    N --> O["Final Confidence\n0–100 Score"]

    O -->|"≥80%"| P["PHISHING"]
    O -->|"40–79%"| Q["SUSPICIOUS"]
    O -->|"<40%"| R["SAFE"]

    P --> S["PostgreSQL\nDetectionLog"]
    Q --> S
    R --> S
    S --> T["Redis Cache\nStore 1hr"]

    P -->|"Async"| U["Blockchain Logger\n(blockchain_utils.py)"]
    U --> V["ThreatLog.sol\nSmart Contract"]
    V --> W["IPFS Evidence\nPackage"]

    N --> X["JSON Response\nto Extension"]
    X --> Y["Popup UI\nResult Display"]
    X -->|"If Phishing\nor Suspicious"| Z["XAI Warning\nOverlay Injected\ninto Page"]

    AA["Analyst Browser"] --> AB["React SOC Dashboard"]
    AB -->|"GET /stats"| E
    AB -->|"GET /logs"| E
    E --> AB

    style P fill:#ff003c,color:#fff
    style Q fill:#ffb000,color:#000
    style R fill:#00c853,color:#fff
    style V fill:#7c4dff,color:#fff
    style W fill:#7c4dff,color:#fff
```

---

## Flow 2 — Chrome Extension Complete Lifecycle

This flow describes everything that happens from the moment a user
navigates to a URL to when they see a result in their browser.

```
sequenceDiagram
    participant User as 👤 User
    participant Tab as 🌐 Browser Tab
    participant Content as content.js
    participant BG as background.js
    participant API as FastAPI Backend
    participant Popup as popup.js

    User->>Tab: Navigates to URL
    Tab->>Content: Injected automatically (all_urls match)

    Note over Content: DOM Feature Extraction begins

    Content->>Content: Read window.location.href → url, url_length
    Content->>Content: Detect @ symbol → has_at_symbol
    Content->>Content: Count subdomains → num_subdomains
    Content->>Content: Check protocol → is_https
    Content->>Content: Query password inputs → has_password_field
    Content->>Content: Check form.action vs page domain → has_cross_origin_form
    Content->>Content: Detect hidden iframes → suspicious_dom_elements

    User->>Popup: Clicks PhishGuard icon
    Popup->>BG: Message: "scan_current_tab"
    BG->>Tab: chrome.scripting.executeScript → extract_features
    Tab->>Content: Message: "extract_features"
    Content-->>BG: Returns feature JSON object

    BG->>API: POST /detect { url, url_length, has_at_symbol, ... }

    API-->>BG: JSON { status, confidence, message, features }

    BG-->>Popup: Forwards API response

    Popup->>Popup: Renders threat level badge\n(Safe / Suspicious / Phishing)
    Popup->>Popup: Renders confidence bar
    Popup->>Popup: Renders XAI reasons list

    alt Status is Phishing or Suspicious
        BG->>Tab: chrome.scripting.executeScript\n→ inject_overlay
        Tab->>Content: Message: "inject_overlay" + { status, confidence, message }
        Content->>Tab: Creates full-screen warning div
        Content->>Tab: Appends to document.body
        Content->>Tab: Blocks page scroll (overflow: hidden)
        User->>Tab: Clicks "Proceed Anyway" (optional)
        Tab->>Content: Event listener removes overlay
    end
```

### Step-by-Step: Extension Feature Extraction

| Step | Action | Signal Captured | Data Type |
| --- | --- | --- | --- |
| 1 | Read `window.location.href` | Full URL string | `string` |
| 2 | Measure URL string length | URL length feature | `int` |
| 3 | Check `url.includes('@')` | AT symbol in URL | `bool` |
| 4 | Split hostname by `.` | Subdomain count | `int` |
| 5 | Check `location.protocol === 'https:'` | HTTPS status | `bool` |
| 6 | `querySelectorAll('input[type="password"]')` | Password form presence | `bool` |
| 7 | Compare `form.action` root to `hostname` root | Cross-origin form (credential theft) | `bool` |
| 8 | Find hidden `iframe` elements | Clickjacking / exfiltration iframes | `int` |

**Output payload sent to backend:**

```
{
  "url": "http://paypa1-secure.com/login",
  "url_length": 34,
  "has_at_symbol": false,
  "num_subdomains": 1,
  "is_https": false,
  "num_redirects": 0,
  "suspicious_dom_elements": 3,
  "has_password_field": true,
  "has_cross_origin_form": true
}
```

---

## Flow 3 — URL Detection 5-Tier Waterfall (Core Pipeline)

This is the central intelligence flow executed on the FastAPI backend
for every URL scan request.

```
flowchart TD
    START(["📥 POST /detect\nReceive features JSON"]) --> T0

    T0["🔑 SHA256 Hash URL\nurl_hash = sha256(url)"]
    T0 --> T1

    subgraph TIER1["⚡ TIER 1 — Tranco Whitelist (O1 Lookup)"]
        T1{"root_domain\nin TRANCO_WHITELIST?"}
    end

    T1 -->|"YES"| R1["✅ Status: Safe\nConfidence: 100%\nMessage: Top 1M Whitelist\nReturn Immediately"]
    T1 -->|"NO"| T2A

    subgraph TIER2["🕐 TIER 2 — WHOIS Domain Age"]
        T2A["Call get_domain_age_days()\nQuery python-whois"]
        T2A --> T2B["Store: domain_age_days\n(-1 if WHOIS fails/timeout)"]
    end

    T2B --> T3

    subgraph TIER3["⚡ TIER 3 — Redis Cache"]
        T3{"redis.get(\nphish_cache:url_hash\n)?"}
    end

    T3 -->|"HIT"| R3["Return Cached Result\n(Expires in 1 hour)\ncached: true"]
    T3 -->|"MISS"| T35

    subgraph TIER35["🌐 TIER 3.5 — Google Safe Browsing API"]
        T35["POST to Safe Browsing v4\nThreat types: MALWARE,\nSOCIAL_ENGINEERING,\nUNWANTED_SOFTWARE"]
        T35 --> T35B{"matches\nin response?"}
    end

    T35B -->|"YES"| R35["🔴 Status: Phishing\nConfidence: 100%\nLog to DB + BC\nCache 1hr\nReturn"]
    T35B -->|"NO / API Down"| T4

    subgraph TIER4["🤖 TIER 4 — XGBoost + MLP Ensemble ML"]
        T4["Extract feature array\n[url_length, has_at,\nnum_subdomains, is_https,\nnum_redirects,\nsuspicious_dom_elements]"]
        T4 --> T4B["model.predict_proba()\nP(safe), P(suspicious),\nP(phishing)"]
        T4B --> T4C["threat_score =\nP(suspicious)×50 +\nP(phishing)×100"]
    end

    T4C --> T45

    subgraph TIER45["🔍 TIER 4.5 — Lexical Heuristics"]
        T45["Shannon Entropy\nof hostname"]
        T45 --> T45B["Levenshtein Typosquatting\nvs 20 top brands"]
        T45B --> T45C["Brand in Subdomain\ncheck"]
        T45C --> T45D["Suspicious Keyword\ndensity count"]
        T45D --> T45E["heuristic_risk_score\n+ reasons list"]
    end

    T45E --> T5

    subgraph TIER5["⚖️ TIER 5 — Multi-Layer Decision Engine"]
        T5["base = ML threat_score"]
        T5 --> T5A["+ heuristic_risk_score"]
        T5A --> T5B{"is_typosquat?"}
        T5B -->|"YES"| T5C["floor at 85%"]
        T5B -->|"NO"| T5D
        T5C --> T5D
        T5D{"has_cross_origin_form?"}
        T5D -->|"YES"| T5E["floor at 95%\nAdd: Zero-Click Theft reason"]
        T5D -->|"NO"| T5F
        T5E --> T5F
        T5F{"domain_age_days?"}
        T5F -->|"< 30 days"| T5G["× 1.5 (new domain spike)"]
        T5F -->|"> 365 days"| T5H["× 0.4 or 0.8\n(established domain)"]
        T5F -->|"-1 unknown"| T5I["No adjustment"]
        T5G --> T5J
        T5H --> T5J
        T5I --> T5J
        T5J["cap at 99.9%\nfinal_confidence"]
    end

    T5J --> VERDICT

    subgraph VERDICT["🏁 Final Verdict"]
        V1{"final_confidence?"}
        V1 -->|"≥ 80"| V2["🔴 PHISHING"]
        V1 -->|"40–79"| V3["🟡 SUSPICIOUS"]
        V1 -->|"< 40"| V4["🟢 SAFE"]
    end

    V2 --> DB["💾 Save to PostgreSQL\nDetectionLog"]
    V3 --> DB
    V4 --> DB
    DB --> CACHE["🔴 Cache in Redis\nTTL: 3600s"]
    V2 -->|"Async Background Task"| BC["⛓️ Blockchain Logger"]
    CACHE --> RESP["📤 JSON Response\n{status, confidence,\ndomain_age_days,\ncached, message,\nfeatures, is_whitelisted}"]
```

### Decision Thresholds Reference

| Condition | Adjustment | Reason |
| --- | --- | --- |
| Heuristic risk > 0 | + heuristic score | Stack evidence from multiple layers |
| `is_typosquat = true` | Floor → 85% minimum | Typosquatting is near-definitive phishing |
| `has_cross_origin_form = true` | Floor → 95% minimum | Password theft to external domain is critical |
| `domain_age_days < 30` | × 1.5 (capped at 99.9%) | New domains are extremely high-risk |
| `domain_age_days > 365` | × 0.4 (or × 0.8 if typosquat) | Established domains are lower risk |
| final ≥ 80% | → “Phishing” | Block + blockchain log |
| final 40–79% | → “Suspicious” | Warning |
| final < 40% | → “Safe” | Allow |

---

## Flow 4 — Visual AI (Computer Vision) Pipeline

Activated when the Chrome extension detects a **password
form** on the current page.

```
flowchart TD
    A["👁️ Trigger:\ncontent.js detects\npassword input on page"] --> B

    B["background.js:\nchrome.tabs.captureVisibleTab()\n→ base64 PNG screenshot"]
    B --> C["POST /vision-scan\n{url, screenshot_base64}"]

    C --> D["vision_engine.py:\nscan_screenshot()"]

    D --> E["decode_base64_image()\nstrip Data URI prefix\nbase64.b64decode()\nnp.frombuffer()→ OpenCV mat"]

    E --> F["Load reference_images/\ndirectory contents\n*.png, *.jpg, *.jpeg"]

    F --> G["For each reference image:"]

    G --> H["calculate_ssim(target, ref)\n1. Resize ref to match target dims\n2. Convert both to grayscale\n3. skimage.ssim(gray1, gray2)\n→ score 0.0–1.0"]

    H --> I{"score >\nhighest so far?"}
    I -->|"YES"| J["Update:\nhighest_similarity = score\nmatched_brand = filename"]
    I -->|"NO"| K["Next reference image"]
    J --> K
    K --> L{"More reference\nimages?"}
    L -->|"YES"| G
    L -->|"NO"| M

    M{"highest_similarity\n≥ 0.80?"}
    M -->|"YES"| N["🔴 is_clone = TRUE\nmatched_brand = brand name\nsimilarity_score = score×100"]
    M -->|"NO"| O["✅ is_clone = FALSE\nNo known UI clone detected"]

    N --> P["Return to extension:\n{is_clone: true,\nmatched_brand: 'Microsoft',\nsimilarity_score: 91.3,\nmessage: 'UI matches Microsoft\nby 91.3%'}"]

    O --> Q["Return: {is_clone: false,\nmatched_brand: null,\nsimilarity_score: 23.1}"]

    P --> R["Extension overlays\nVisual Phishing Warning\nwith brand name and\nsimilarity score"]
```

### SSIM Algorithm Internals

```
Step 1: Extension captures tab screenshot → base64 PNG
Step 2: Backend decodes PNG → NumPy array → OpenCV BGR matrix
Step 3: For each brand reference image in /reference_images/:
   a. Resize reference image to match target screenshot dimensions
   b. Convert both to grayscale (single-channel)
   c. Compute SSIM:
      SSIM(x,y) = [2μxμy + C1][2σxy + C2] / [(μx² + μy² + C1)(σx² + σy² + C2)]
      where: μ = local mean, σ = local variance, C1/C2 = stability constants
   d. Score range: 0.0 (completely different) → 1.0 (structurally identical)
Step 4: Track brand with highest similarity score
Step 5: Threshold check: if max_score ≥ 0.80 → IS_CLONE = true
```

---

## Flow 5 — Blockchain Audit Logging Flow

Executes **asynchronously** as a FastAPI background task
— never blocking the HTTP response.

```
sequenceDiagram
    participant API as FastAPI main.py
    participant BG as BackgroundTask Queue
    participant BU as blockchain_utils.py
    participant W3 as Web3.py
    participant HH as Ethereum Sepolia Testnet Node
    participant SC as ThreatLog.sol
    participant IPFS as IPFS (Pinata)

    API->>API: final verdict = "Phishing"
    API->>BG: background_tasks.add_task(\nprocess_blockchain_bg,\nurl_hash, features_dict)
    API-->>Extension: Immediate JSON response\n(NOT waiting for blockchain)

    Note over BG: Runs after HTTP response is sent

    BG->>BU: log_to_blockchain(url_hash, features_dict)
    BU->>W3: w3.is_connected() ?
    W3->>HH: ETH RPC health check
    HH-->>W3: Connected ✅

    BU->>SC: contract.functions.isLogged(url_hash).call()
    SC-->>BU: false → Not yet logged

    BU->>IPFS: upload_evidence_to_ipfs(\nurl_hash,\nfeatures_dict)
    Note over IPFS: Packages: URL hash +\nall DOM features +\ntimestamp as JSON\nPins to IPFS node
    IPFS-->>BU: Returns ipfs_hash (CID)\n"QmXk3d9...Ev1d3nc3"

    BU->>SC: contract.functions.addLog(\nurl_hash,\nipfs_hash\n).transact({from: account})

    SC->>SC: logs.push(PhishingLog{\n  urlHash: url_hash,\n  ipfsHash: ipfs_hash,\n  timestamp: block.timestamp,\n  reporter: msg.sender\n})
    SC->>SC: emit LogAdded(urlHash,\nipfsHash, timestamp, reporter)

    HH-->>W3: tx_hash
    W3->>HH: wait_for_transaction_receipt(tx_hash)
    HH-->>W3: receipt { status: 1 }
    W3-->>BU: Transaction confirmed ✅
    BU->>BU: Print: "Successfully logged\n{url_hash} with {ipfs_hash}"
```

### On-Chain Data Structure

```
ThreatLog Contract Storage:
┌─────────────────────────────────────────────────────────┐
│ PhishingLog Entry #N                                     │
│ ├── urlHash:   "a3f4b2...8e9d" (SHA256 of URL)          │
│ ├── ipfsHash:  "QmXk3d...nc3" (IPFS CID of evidence)    │
│ ├── timestamp: 1712347890 (Unix epoch, block time)       │
│ └── reporter:  0x3f4b...2e8a (Ethereum address)          │
└─────────────────────────────────────────────────────────┘

IPFS Evidence Package (linked from ipfsHash):
{
  "url_hash": "a3f4b2...8e9d",
  "url_length": 78,
  "has_at_symbol": false,
  "num_subdomains": 3,
  "is_https": false,
  "suspicious_dom_elements": 5,
  "has_cross_origin_form": true,
  "heuristics": {
    "is_typosquat": true,
    "entropy": 4.73,
    "reasons": ["Typosquatting 'paypal'", "High entropy"]
  }
}
```

---

## Flow 6 — MLOps Automated Retraining Pipeline

Triggered by admin via `POST /admin/retrain`. Ensures the
XGBoost + MLP Ensemble model stays current as phishing patterns evolve.

```
flowchart TD
    A(["👨‍💼 Admin:\nPOST /admin/retrain"]) --> B

    B["FastAPI:\nbackground_tasks.add_task(\nbackground_retrain)"]
    B --> C["Return immediately:\n'Retraining initiated'"]

    C --> D["Background: run_pipeline()"]

    D --> E["Open PostgreSQL Session\nSessionLocal()"]
    E --> F["Query: DetectionLog\nWHERE status =\n'User_Reported_Phishing'"]
    F --> G{"Any reports\nfound?"}
    G -->|"NO"| H["Print: No new reports\nSkip retraining\nreturn False"]
    G -->|"YES, N reports"| I

    I["For each report:\nBuild feature row:\n{\n  url_length,\n  has_at_symbol: 0/1,\n  num_subdomains,\n  is_https: 0/1,\n  num_redirects: 0,\n  suspicious_dom_elements,\n  label: 2  ← Phishing\n}"]

    I --> J["Update DB: status →\n'Phishing'\n(prevents re-ingestion)"]
    J --> K["db.commit()\ndb.close()"]

    K --> L["df_new = pd.DataFrame(new_data)"]
    L --> M{"processed_features.csv\nexists?"}
    M -->|"YES"| N["df_new.to_csv(\nprocessed_features.csv,\nmode='a',\nheader=False\n) ← APPEND"]
    M -->|"NO"| O["Error: Base dataset\nnot found\nreturn False"]

    N --> P["train_model()\n↓\nLoad processed_features.csv\n↓\nX = features columns\ny = label column\n↓\ntrain_test_split 80/20\n↓\nRandomForestClassifier.fit(X_train, y_train)\n↓\njoblib.dump → xgboost_mlp_model.pkl"]

    P --> Q["run_pipeline() returns True"]
    Q --> R["background_retrain()\nchecks success == True"]
    R --> S["reload_model()\n↓\njoblib.load(\nxgboost_mlp_model.pkl)\n↓\nglobal model = new_model"]

    S --> T["✅ Live model updated\nZero server downtime\nAll new /detect calls\nuse retrained model"]

    style T fill:#00c853,color:#fff
    style H fill:#ff6d00,color:#fff
    style O fill:#ff003c,color:#fff
```

### Retraining Data Flow

```
User Action          →  Report stored in DB (status: User_Reported_Phishing)
Admin Trigger        →  POST /admin/retrain → BackgroundTask invoked
Pipeline Step 1      →  Query DB for all User_Reported_Phishing records
Pipeline Step 2      →  Convert reports to feature rows (label=2/Phishing)
Pipeline Step 3      →  Append rows to processed_features.csv (~7.7MB base)
Pipeline Step 4      →  Re-run RandomForestClassifier.fit() on full dataset
Pipeline Step 5      →  Save new xgboost_mlp_model.pkl (overwrites old)
Pipeline Step 6      →  Hot-reload: global model variable = joblib.load(pkl)
Result               →  All future /detect calls now use the updated model
Downtime             →  ZERO — server never restarts
```

---

## Flow 7 — SOC Dashboard Data Flow

How the React frontend communicates with the backend to render the
analyst’s view.

```
sequenceDiagram
    participant Analyst as 👨‍💻 Security Analyst
    participant React as React Dashboard (App.jsx)
    participant API as FastAPI Backend

    Analyst->>React: Opens dashboard in browser

    React->>API: GET /stats
    API->>API: COUNT all DetectionLog rows\nBREAK DOWN by status\nGENERATE 7-day progression
    API-->>React: { total_scanned, phishing_detected,\nsuspicious_detected, safe_detected,\nmodel_accuracy: 94.5,\nfalse_positive_rate: 1.2,\nprogression: [{name:"Mon", score:87}, ...] }

    React->>React: Render KPI cards\n(Total / Phishing / Suspicious / Safe)
    React->>React: Render Recharts LineChart\nfrom progression array
    React->>React: Render accuracy + FPR metrics

    React->>API: GET /logs?skip=0&limit=20
    API->>API: Query DetectionLog\nORDER BY timestamp DESC\nOFFSET 0 LIMIT 20
    API-->>React: Array of LogOut schema objects\n[{id, url, status, confidence,\ntimestamp, logged_to_blockchain, ...}]

    React->>React: Render scrollable log table\nColor-coded rows by status

    loop Poll every 30 seconds
        React->>API: GET /stats
        React->>API: GET /logs?skip=0&limit=20
        API-->>React: Updated data
        React->>React: Re-render components
    end

    Analyst->>React: Types in search box
    React->>React: Client-side filter\nlog entries by URL text

    Analyst->>React: Clicks "Retrain Model"
    React->>API: POST /admin/retrain
    API-->>React: { message: "Retraining initiated" }
    React->>React: Show success toast
```

### API Endpoints Used by Dashboard

| Endpoint | Method | Purpose | Response Fields |
| --- | --- | --- | --- |
| `/stats` | GET | Aggregate metrics + 7-day chart | `total_scanned`, `phishing_detected`, `suspicious_detected`, `safe_detected`, `model_accuracy`, `false_positive_rate`, `progression[]` |
| `/logs` | GET | Paginated detection history | `id`, `url`, `status`, `confidence`, `timestamp`, `logged_to_blockchain` |
| `/admin/retrain` | POST | Trigger MLOps pipeline | `message` |
| `/detect` | POST | Manual URL scan from SOC | Full detection response |
| `/report` | POST | Mark URL as phishing | `message` |

---

## Flow 8 — End-to-End Complete User Journey

This traces the **complete lifecycle** from a user
visiting a phishing URL to the threat being permanently recorded.

```
TIME 0ms     │ User types "paypa1-secure.com/login" into browser address bar
             │
TIME 10ms    │ Browser loads page, Chrome injects content.js
             │
TIME 30ms    │ content.js executes:
             │  ├── url = "http://paypa1-secure.com/login"
             │  ├── url_length = 36
             │  ├── has_at_symbol = false
             │  ├── num_subdomains = 1
             │  ├── is_https = false ← SUSPICIOUS
             │  ├── has_password_field = true
             │  ├── has_cross_origin_form = true ← CRITICAL
             │  └── suspicious_dom_elements = 7
             │
TIME 50ms    │ User clicks PhishGuard icon → popup.js opens
             │ background.js calls extract_features → content.js
             │ Features JSON assembled
             │
TIME 60ms    │ POST /detect sent to FastAPI backend
             │
TIME 62ms    │ TIER 1: SHA256("http://paypa1-secure.com/login")
             │         "paypa1-secure.com" NOT in Tranco whitelist → proceed
             │
TIME 120ms   │ TIER 2: WHOIS query for "paypa1-secure.com"
             │         domain_age_days = 3 ← BRAND NEW DOMAIN (HIGH RISK)
             │
TIME 125ms   │ TIER 3: Redis cache miss → proceed
             │
TIME 250ms   │ TIER 3.5: Google Safe Browsing check
             │           API returns: no matches (new domain, not yet in list)
             │           → proceed to ML
             │
TIME 260ms   │ TIER 4: XGBoost + MLP Ensemble inference
             │         features_array = [36, 0, 1, 0, 0, 7]
             │         P(safe)=0.02, P(suspicious)=0.18, P(phishing)=0.80
             │         threat_score = (0.18×50) + (0.80×100) = 89.0
             │
TIME 270ms   │ TIER 4.5: Heuristics engine
             │           domain = "paypa1-secure"
             │           → Levenshtein("paypa1", "paypal") = 1 ← TYPOSQUAT!
             │           → heuristic_risk_score = 40.0
             │           → reasons = ["Typosquatting 'paypal'"]
             │           → is_https = false AND has_password = true
             │           → suspicious_dom_elements += 2 → total = 9
             │
TIME 275ms   │ TIER 5: Decision Engine
             │         base = 89.0 + 40.0 = 129.0 → capped at 99.9
             │         is_typosquat = true → floor at 85% (already above)
             │         has_cross_origin_form = true → floor at 95% (already above)
             │         domain_age_days = 3 (<30) → × 1.5 → 99.9 (cap reached)
             │         final_confidence = 99.9%
             │         status = "PHISHING"
             │
TIME 280ms   │ Save to PostgreSQL DetectionLog
             │ Cache result in Redis (TTL: 3600s)
             │ Queue BackgroundTask: blockchain logging
             │
TIME 285ms   │ HTTP Response returned to extension:
             │   {
             │     "status": "Phishing",
             │     "confidence": 99.9,
             │     "message": "Typosquatting 'paypal' | Zero-Click Theft: ...",
             │     "domain_age_days": 3,
             │     "logged_to_blockchain": true
             │   }
             │
TIME 290ms   │ popup.js renders:
             │   🔴 PHISHING — 99.9% confidence
             │   ⚠️ Typosquatting detected (mimicking 'paypal')
             │   ⚠️ Zero-Click Theft: Password form submits to external domain
             │   Domain Age: 3 days old
             │
TIME 295ms   │ background.js injects overlay into page tab
             │ Full-screen red warning appears over the phishing site:
             │   "CRITICAL SECURITY ALERT: PHISHING"
             │   "PhishGuard AI has blocked this page."
             │   XAI reasons displayed
             │
TIME 2000ms  │ [ASYNC - user unaffected]
             │ BackgroundTask runs: log_to_blockchain()
             │ IPFS evidence packaged with all features
             │ ThreatLog.sol: addLog(url_hash, ipfs_hash) called
             │ Transaction mined on Ethereum Sepolia Testnet
             │ Permanent on-chain record created ✅
             │
TIME 2500ms  │ [SOC Dashboard - in parallel]
             │ Security analyst sees new PHISHING entry in live log
             │ 7-day security score chart updates downward
             │ Blockchain icon shows: ⛓️ Logged
```

---

## Flow 9 — Data Storage Architecture

```
flowchart LR
    subgraph MEMORY["In-Memory (Process Start)"]
        TW["Tranco Whitelist\nPython set()\n~1M domains\nO(1) lookup"]
        XGBoost+MLP["XGBoost + MLP Ensemble Model\nxgboost_mlp_model.pkl\n~12MB loaded\nPredict in ms"]
    end

    subgraph REDIS["Redis (Cache Layer)"]
        RC["phish_cache:hash\nTTL: 3600s (normal)\nTTL: 86400s (reported)\nKey: SHA256(url)"]
    end

    subgraph POSTGRES["PostgreSQL (Persistent Store)"]
        DL["DetectionLog Table\n────────────────\nid (PK)\nurl (TEXT)\nurl_hash (TEXT, unique)\nstatus (VARCHAR)\nconfidence (FLOAT)\ntimestamp (DATETIME)\nlogged_to_blockchain (BOOL)\nurl_length (INT)\nhas_at_symbol (BOOL)\nnum_subdomains (INT)\nis_https (BOOL)\nsuspicious_dom_elements (INT)"]
    end

    subgraph BLOCKCHAIN["Blockchain (Immutable Log)"]
        SC["ThreatLog.sol\nPhishingLog[]\n────────────\nurlHash (string)\nipfsHash (string)\ntimestamp (uint256)\nreporter (address)"]
        IP["IPFS\nEvidence JSON\nCID pointer"]
        SC --> IP
    end

    subgraph FILESYSTEM["Filesystem (ML Artifacts)"]
        CSV["processed_features.csv\n~7.7MB feature dataset"]
        PKL["xgboost_mlp_model.pkl\n~12MB trained model"]
        REF["reference_images/\nbrand screenshot library"]
        TR["tranco.txt\n~15MB domain list"]
    end

    API["FastAPI /detect"] --> MEMORY
    API --> REDIS
    API --> POSTGRES
    API -->|"async"| BLOCKCHAIN
    ML["ML Training"] --> FILESYSTEM
    VIS["Vision Engine"] --> REF
```

---

## Summary: Flow Timing Overview

| Flow | Trigger | Total Time | Blocking? |
| --- | --- | --- | --- |
| Whitelist hit | Any URL on Tranco | ~62ms | Yes (sync, but fast) |
| Cache hit | Repeat URL | ~65ms | Yes (sync, but fast) |
| Full ML pipeline | New unknown URL | ~280–600ms | Yes (sync) |
| Visual AI scan | Password form detected | ~200–500ms | Yes (sync) |
| Blockchain logging | Phishing verdict | ~2,000–10,000ms | **No (async background)** |
| MLOps retraining | Admin trigger | ~30,000–120,000ms | **No (async background)** |
| SOC dashboard refresh | 30s interval | ~100ms per request | No (independent) |