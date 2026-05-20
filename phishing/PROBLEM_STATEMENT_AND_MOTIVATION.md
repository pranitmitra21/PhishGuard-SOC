# PhishGuard SOC — Detailed Problem Statement
---
## 1. Background & The Global Threat Landscape
Phishing is the single most common form of cybercrime in the world today. It is a socially engineered attack in which a malicious actor creates a fraudulent website or URL that impersonates a legitimate one — such as a bank, e-commerce portal, or email provider — to deceive users into surrendering sensitive information such as passwords, credit card numbers, or authentication tokens.

According to industry reports:
- **Over 3.4 billion phishing emails** are sent every single day globally.
- Phishing attacks account for **more than 36% of all data breaches** (Verizon DBIR).
- The **average financial loss per phishing incident** for organizations has crossed **$4.9 million USD**.
- A new phishing website is created approximately **every 20 seconds**, making reactive blocklists inadequate by design.
- **90% of all cyberattacks begin with a phishing attempt**, making it the primary attack vector across industries.

Despite decades of security research, phishing remains devastatingly effective because it targets the weakest link in any security system: the **human user**. Users cannot be expected to manually inspect every URL they visit for subtle deception — especially when attackers use techniques like typosquatting (`paypa1.com`), subdomain injection (`paypal.secure-login.xyz`), and visual UI cloning that are virtually invisible to the human eye.

---
## 2. Core Problems Being Solved

### Problem 1 — No Real-Time Browser-Level Protection
**The Gap**: Existing antivirus software and firewalls operate at the network layer and are installed on devices. They cannot inspect the rich contextual signals available *inside a live webpage* — such as the structure of HTML forms, whether a password field submits to an external domain, or the presence of hidden iframes.

**The Consequence**: A user visiting a visually identical fake banking page in Chrome gets no warning. By the time the network-level tool detects an anomaly (if it does), the user’s credentials may already have been submitted.

**PhishGuard’s Answer**: A **Chrome Extension (Manifest V3)** runs a deep DOM feature extractor inside every open webpage. It captures:
- Whether the page hosts a password form that submits to a **cross-origin domain** (Zero-Click Credential Theft)
- The presence of hidden or zero-dimension `<iframe>` elements (classic click-jacking and data exfiltration technique)
- URL-level signals like subdomain count, `@` symbol presence, and HTTPS status — all extracted live from the active browser tab

---
### Problem 2 — Static Blocklists Are Reactive, Not Proactive
**The Gap**: The most widely used defenses — browser built-in blocklists, Google Safe Browsing, and antivirus URL databases — are **reactive systems**. A URL must first be reported, verified, and then added to the blocklist. This process typically takes **24 to 72 hours**.

**The Consequence**: Phishing campaigns are designed to be ephemeral. Attackers launch a site, harvest credentials for 48 hours, and then abandon the domain — often before any blocklist is updated. Studies show that over **60% of phishing sites are active for less than 24 hours**.

**PhishGuard’s Answer**: Rather than relying solely on blocklists, PhishGuard uses a **trained Machine Learning model (XGBoost + Multi-Layer Perceptron (MLP) Ensemble)** capable of analyzing a URL it has never seen before and predicting its threat probability. The model was trained on a **50,000+ verified phishing vectors dataset** of real phishing and benign URLs, allowing it to generalize to brand-new, previously unseen attack patterns.

---
### Problem 3 — URL String Analysis Alone Is Insufficient
**The Gap**: Even ML-based URL classifiers that analyze URL strings are vulnerable to **zero-day visual phishing** — attacks where an adversary compromises a legitimate, trusted domain (or uses a brand-new domain with a clean reputation) and hosts a pixel-perfect clone of a bank or corporate login page. The URL passes all string-based checks because the domain itself is not malicious.

**The Consequence**: A user visits `accounts.verylegit-corp.com/microsoft-login` — the URL is HTTPS, has no suspicious subdomains, has no typosquatting, and passes every lexical check. But the page is a cloned Microsoft login page.

**PhishGuard’s Answer**: When the Chrome extension detects a **password form on a page**, it captures a screenshot of the visible page and sends it to the backend `/vision-scan` endpoint. The **Visual AI Engine** uses **OpenCV** and the **SSIM (Structural Similarity Index)** algorithm to compare the live screenshot against a library of known brand login pages. If any match exceeds 80% visual similarity, the page is flagged as a UI clone regardless of URL analysis results.

---
### Problem 4 — Detection Without Explanation Is Unacceptable
**The Gap**: Many security tools give a binary verdict: “safe” or “dangerous.” They provide no explanation to the user about *why* a site was flagged. This creates two serious problems:
1. **User distrust**: Users who don’t understand the reason are more likely to dismiss the warning and proceed anyway.
2. **High false-positive frustration**: If a legitimate site is flagged with no reason given, users lose confidence in the tool entirely.

This lack of transparency is known as the **Black Box AI Problem** in cybersecurity.

**PhishGuard’s Answer**: Every detection verdict includes a structured **Explainable AI (XAI) report** — a plain-English list of exactly which signals triggered the alert:
> *“⚠️ Typosquatting detected (mimicking ‘paypal’)”*
> *“⚠️ Brand name ‘google’ used deceptively in subdomain”*
> *“⚠️ Zero-Click Theft: Password form submits to external tracking domain!”*
> *“⚠️ High hostname entropy (4.73) — possible bot-generated domain”*

These reasons are displayed in the browser extension popup and also injected as a **full-screen blocking overlay** directly onto the suspicious webpage, mirroring how enterprise SIEM (Security Information and Event Management) tools present structured threat intelligence.

---
### Problem 5 — No Tamper-Proof Record of Phishing Events
**The Gap**: When a phishing attack is detected and logged, the log record is typically stored in a centralized SQL database. Centralized records are:
- **Mutable** — a compromised admin or insider threat can delete or modify them.
- **Single points of failure** — if the server is lost, so is the evidence.
- **Non-auditable** — there is no way for an external party to independently verify when and what was logged.

For cybercrime prosecutions, insurance claims, and regulatory compliance (GDPR, HIPAA), a verifiable, immutable audit trail is not optional — it is legally and procedurally essential.

**PhishGuard’s Answer**: Every URL confirmed as Phishing is logged asynchronously to an **Ethereum smart contract** (`ThreatLog.sol` deployed on a Ethereum Sepolia Testnet). The contract stores:
- The **SHA256 hash of the URL** (privacy-preserving — the actual URL is not on-chain)
- An **IPFS content identifier (CID)** pointing to the full evidence package (DOM features, scan metadata)
- An on-chain **timestamp** and the **reporter’s Ethereum address**

Once written, this record **cannot be altered or deleted by anyone** — including system administrators. The blockchain’s immutability transforms the threat log from a mutable database record into a legally defensible, cryptographically verified audit trail.

---
### Problem 6 — Security Teams Have No Centralized Visibility
**The Gap**: End users only see a per-page result. But an organization’s **Security Operations Center (SOC)** needs a bird’s-eye view:
- How many phishing attempts were blocked today?
- Is the attack rate increasing over time?
- Which specific URLs were targeted and when?
- What is the model’s current accuracy and false positive rate?

Without centralized threat visualization, security analysts are flying blind and cannot detect coordinated, large-scale phishing campaigns targeting an organization.

**PhishGuard’s Answer**: A dedicated **React-based SOC Dashboard** provides security analysts with:
- Real-time threat counts (Phishing / Suspicious / Safe / Total)
- A **7-day Security Score trend chart** showing the organization’s threat posture over time
- A **live, scrollable detection log** with full feature vectors per scan
- A **global URL search** capability across all historical scan data
- Model performance metrics (accuracy, false positive rate)

This transforms PhishGuard from a personal browser tool into a centralized enterprise threat monitoring platform.

---
### Problem 7 — ML Models Become Stale Over Time (Model Drift)
**The Gap**: Phishing techniques evolve constantly. A model trained on data from 6 months ago may perform poorly against today’s attacks because:
- New phishing keywords emerge (e.g., “covid-relief”, “ukraine-aid”, “AI-verification”)
- New attack patterns appear (QR code phishing, SMS phishing redirects)
- The distribution of phishing vs. safe URLs in the real world shifts

This problem is called **Model Drift** — and it is the Achilles’ heel of static ML-based security systems.

**PhishGuard’s Answer**: An **automated MLOps Retraining Pipeline** solves this at its root:
1. Users can report false negatives (missed phishing) via a dedicated `/report` endpoint.
2. Reported URLs are stored in the PostgreSQL database with label `User_Reported_Phishing`.
3. When an admin triggers `/admin/retrain`, a **background task** collects all reports, appends them as new training samples to the master dataset CSV, runs a **full XGBoost + MLP Ensemble retraining**, and **hot-reloads the new model file into memory** — all without restarting the server or causing downtime.

The system continuously improves its own accuracy from real-world feedback — a key characteristic of production-grade enterprise ML systems.

---
## 3. Why Existing Solutions Are Inadequate

| Existing Solution | What It Misses |
| :--- | :--- |
| **Google Safe Browsing** | Reactive blocklist — misses attacks in first 24–72 hrs; no DOM analysis |
| **Browser built-in warnings** | Simple heuristics only; no ML, no visual analysis, no XAI |
| **Antivirus software** | Network-level only; no in-page DOM inspection; no blockchain audit |
| **PhishTank / OpenPhish** | Community-reported databases — days-old data; no real-time inference |
| **Academic ML classifiers** | URL-string only; no live DOM features; no retraining; no UI |
| **Enterprise SIEM tools** | Expensive, complex, no browser-native integration; no visual AI |

---
## 4. Scope and Boundaries
**In Scope:**
- Detection of phishing via URL heuristics, ML inference, and visual AI
- Real-time detection at the browser level for every page visited
- Blockchain-based immutable logging for confirmed threats
- SOC dashboard for organizational threat monitoring
- Automated model retraining from user feedback

**Out of Scope:**
- Email phishing / attachment scanning
- Detection of phishing via phone calls (vishing) or SMS (smishing)
- Real-time geographic IP threat mapping (planned feature)
- Full RBAC authentication between analyst roles (planned feature)
- Deployment to a public cloud (currently local Docker setup)

---
## 5. Formal Problem Statement
> **Current web users and organizational security teams lack a unified, real-time defense system capable of detecting phishing attacks at the browser level using multiple converging intelligence layers. Existing solutions are either reactive blocklists that fail within the first 24–72 hours of a campaign, or isolated ML classifiers that analyze only URL strings and provide no explainability, no visual detection capability, no tamper-proof incident logging, and no mechanism for continuous self-improvement. There exists a critical need for an end-to-end, browser-native phishing detection platform that integrates live DOM feature extraction, multi-layer AI inference (machine learning, lexical heuristics, and computer vision), Explainable AI for human-readable threat reporting, a blockchain-backed immutable audit trail, and an automated MLOps retraining pipeline — all visible through a centralized SOC dashboard — to provide proactive, adaptive, and trustworthy protection against one of the most prevalent and damaging forms of cybercrime.**

---
## 6. Research Questions Addressed
1. Can a multi-layer detection engine (ML + Heuristics + Vision + Threat Intel) achieve higher accuracy and lower false positives than any single-layer approach?
2. Can live DOM features extracted directly from a browser page significantly improve phishing detection beyond URL-string analysis alone?
3. Can visual SSIM-based screenshot comparison effectively identify zero-day UI clone attacks that evade URL-based systems?
4. Can a blockchain smart contract serve as a practical, tamper-proof incident logging system within a real-time threat detection pipeline?
5. Can an online MLOps retraining loop prevent model drift and sustain detection accuracy as phishing techniques evolve over time?

---
# PhishGuard SOC — Motivation and Objectives
---
## Part A: Motivation

### A.1 The Human Cost of Phishing — Why This Problem Matters
Phishing is not merely a technical problem — it is a human crisis with real-world consequences. Every day, ordinary individuals lose their life savings when their bank credentials are stolen through a fake login page. Employees unknowingly hand over corporate VPN access to attackers impersonating their IT department. Students get their email accounts hijacked through fraudulent university portals. Healthcare workers inadvertently expose patient records by clicking a link that mimics a hospital intranet login.

These are not hypothetical scenarios. They are documented, recurring incidents that represent the real damage phishing causes to real people. The 2023 FBI Internet Crime Report recorded over **$10.3 billion in losses** attributable to cybercrime, with phishing as the most reported attack category for the third consecutive year.

Despite this, the average internet user has almost no meaningful protection beyond a browser warning that most people have learned to dismiss without reading.

This fundamental mismatch — between the sophistication and scale of the attack and the inadequacy of the user’s defense — is the single most powerful motivation behind building PhishGuard SOC.

---
### A.2 The Inadequacy of the Status Quo
The motivation was further strengthened by a critical observation during research: **every existing phishing defense has at least one fatal blind spot.**

#### The Blocklist Trap
Google Safe Browsing and browser-built-in warning systems are fundamentally **reactive**. They function like a database of known criminals — useful only after someone has already been victimized and the attacker has been identified. Since a typical phishing campaign is active for less than 24 hours, and blocklist updates take 24–72 hours to propagate, there is a **guaranteed window of vulnerability** for every new campaign.

PhishGuard is motivated to close this window with a proactive, learned intelligence layer that can evaluate URLs it has *never seen before*.

#### The URL-Only Fallacy
Most academic and commercial ML-based detectors analyze only the URL string. This creates an entire class of undetectable attacks: **visual phishing**. An attacker can register a domain with a clean reputation (`secure-auth-portal.net`), host a pixel-perfect copy of the Microsoft login page, get HTTPS certification, and pass every URL-based check. The URL is “safe” — but the page is a trap.

The observation that **no widely available consumer tool combines URL analysis with live visual page analysis** was a core motivation for building the Computer Vision pipeline in PhishGuard.

#### The Black Box Problem
Existing tools say “this site is dangerous.” They do not say why. Security researchers have extensively documented that users are far less likely to comply with a warning they don’t understand. A teenager who sees “Dangerous site!” with no further explanation may click “proceed anyway” — particularly if the site *looks* like the real PayPal. Explainability is not a luxury; it is a **security requirement**.

This motivated the XAI (Explainable AI) design philosophy at the core of PhishGuard: every verdict comes with a structured, human-readable justification written in plain language.

#### The Audit Trail Problem
In enterprise environments, a phishing incident is a **legal and compliance event**. Organizations need to demonstrate to regulators, auditors, and insurers that a threat was detected at a specific time with specific evidence for a specific URL. A record in a SQL database — which can be accidentally deleted, corrupted, or maliciously altered — does not satisfy this requirement.

The motivation to incorporate a **blockchain-backed immutable audit trail** arose directly from studying how enterprise security teams struggle to maintain verifiable evidence chains post-incident. Blockchain technology, by its very nature, provides exactly the tamper-proof, cryptographically verified record that compliance frameworks demand.

#### The Stagnation Problem
A trained ML model is a snapshot of the threat landscape at one moment in time. Phishing attackers adapt constantly — new keywords, new brand targets, new URL patterns. A model trained six months ago is measurably less accurate today. Yet most systems deploy a model and never update it.

The motivation to build an **MLOps continuous retraining pipeline** comes from the observation that the gap between a trained model and the real world grows every day it goes unaddressed. A phishing detector that cannot learn is not a long-term solution — it is a decaying one.

---
### A.3 The Academic and Engineering Motivation
Beyond the societal need, PhishGuard is motivated by academic curiosity and engineering ambition across several disciplines:

#### Bridging Theory and Practice
Academic courses in Machine Learning teach classification algorithms on clean, static datasets. PhishGuard asks: *What does it look like when XGBoost + MLP Ensemble is deployed in a live, production-grade system* with asynchronous background tasks, database dependencies, Redis caching, and hot model reloading? The motivation is to answer that question with a fully functional system.

#### Multi-Discipline Integration
Phishing detection sits at the intersection of:
- **Natural Language Processing** (URL string analysis, entropy, n-gram keyword matching)
- **Computer Vision** (SSIM screenshot comparison)
- **Distributed Systems** (blockchain, async task queues)
- **Web Security** (DOM analysis, cross-origin forms, XSS patterns)
- **MLOps** (automated pipelines, model versioning, drift detection)
- **Full-Stack Engineering** (React SOC dashboard, FastAPI, Docker)

The motivation is to produce a system that demonstrates genuine cross-domain engineering competence, not just isolated knowledge in one area.

#### Demonstrating that Security Can Be Accessible
Enterprise cybersecurity tools like Splunk, CrowdStrike, and Darktrace cost tens of thousands of dollars per year. PhishGuard is motivated by the belief that the *core principles* of these tools — threat intelligence, behavioral analysis, immutable logging, SOC visibility — can be architected and demonstrated at a student level using open-source technology.

---
### A.4 The Engineering Challenge as Motivation
Certain specific engineering challenges served as direct motivators:

| Challenge | Why It Was Motivating |
| :--- | :--- |
| Can ML generalize to unseen phishing URLs? | Tests the true power of learned generalization over brittle rules |
| Can Computer Vision catch what NLP cannot? | Tests whether visual similarity is a viable signal in a latency-constrained system |
| Can a Solidity smart contract serve as a practical audit log? | Tests blockchain utility beyond cryptocurrency, in a real data pipeline |
| Can the model retrain itself from user feedback without downtime? | Tests production-grade MLOps principles in a real system |
| Can a browser extension extract meaningful security signals from live DOM? | Tests the boundary of what JavaScript in a content script can actually observe |

Each of these questions required original engineering work — not the application of an existing tutorial or tool, but the design and implementation of a novel system component.

---
## Part B: Objectives

### B.1 Primary Objectives

#### Objective 1 — Build a Real-Time, Browser-Native Threat Detection System
Develop a **Chrome Extension (Manifest V3)** capable of inspecting every webpage at load time and extracting both URL-level and DOM-level security signals without degrading browser performance. The extension must:
- Extract at minimum 8 security features per page visit
- Detect cross-origin form submission (credential exfiltration)
- Detect hidden iframe elements
- Send structured feature vectors to the backend within 500ms
- Render results to the user in a visually clear, non-intrusive popup UI

---
#### Objective 2 — Implement a Multi-Layer AI Detection Engine
Design and deploy a **5-tier cascading detection pipeline** that combines multiple intelligence sources, each compensating for the blind spots of the others:
- **Tier 1**: Tranco Top-1M whitelist (O(1) set lookup for trusted domains)
- **Tier 2**: WHOIS domain age verification (new domains flagged as higher risk)
- **Tier 3**: Redis caching (prevent redundant inference on repeated URLs)
- **Tier 4**: Google Safe Browsing API integration (real-time external threat intelligence)
- **Tier 5**: Local XGBoost + MLP ML ensemble inference + Lexical Heuristics scoring

The engine must produce a final confidence score on a **0–100 scale** and assign one of three verdict labels: `Safe`, `Suspicious`, or `Phishing`.

---
#### Objective 3 — Train a High-Accuracy Machine Learning Model
Train a **XGBoost + Multi-Layer Perceptron (MLP) Ensemble** on a merged dataset of real phishing and benign URLs to:
- Achieve a baseline detection accuracy of **≥ 90%** on the test partition
- Minimize false positives (legitimate sites flagged as phishing) to **< 5%**
- Produce calibrated probability outputs (`predict_proba`) for use in weighted confidence scoring
- Be serialized and deployable as a `.pkl` model file playable from a FastAPI server

---
#### Objective 4 — Develop an Advanced Lexical Heuristics Layer
Implement a **rule-based linguistic analysis engine** that catches attack patterns invisible to the ML model alone:
- **Shannon Entropy calculation** to detect randomly generated (DGA) hostnames
- **Levenshtein Distance typosquatting detector** against a corpus of 20 major targeted brands, including homoglyph substitution (`0→o`, `1→l`, `!→i`)
- **Brand-in-subdomain injection detector** (e.g., `paypal.attacker-domain.com`)
- **Suspicious keyword density scoring** with a curated vocabulary of phishing-associated terms

All heuristic signals must be surfaced as human-readable reason strings passed to the frontend.

---
#### Objective 5 — Implement a Visual AI Zero-Day Detection Pipeline
Build a **Computer Vision module** using OpenCV and scikit-image that:
- Accepts a base64-encoded screenshot from the Chrome extension
- Decodes it into an OpenCV image matrix and normalizes dimensions
- Computes **SSIM (Structural Similarity Index)** against every reference brand login page
- Flags pages with ≥ 80% visual similarity as confirmed UI clones
- Returns the matched brand name and similarity score to the frontend for XAI display

This objective addresses attacks that operate on compromised legitimate domains, which bypass all URL-based detection methods.

---
#### Objective 6 — Create an Immutable Blockchain Audit Trail
Design and deploy a **Solidity smart contract** (`ThreatLog.sol`) on an Ethereum Sepolia Testnet (Ethereum Sepolia Testnet) that:
- Stores the **SHA256 hash** of every confirmed phishing URL (privacy-preserving — not the raw URL)
- Stores an **IPFS content identifier** linking to full forensic evidence (DOM features, scan metadata)
- Records an on-chain **UNIX timestamp** and the **reporter’s Ethereum address**
- Provides an `isLogged()` function to prevent duplicate blockchain entries
- Is called **asynchronously** as a FastAPI background task so transaction latency (~2–10s) never blocks the HTTP response

---
#### Objective 7 — Build an Automated MLOps Retraining Pipeline
Implement a **zero-downtime continuous learning system** that:
- Accepts user-reported false negatives via a `POST /report` API endpoint
- Stores reports in the PostgreSQL database with a distinct `User_Reported_Phishing` label
- On admin trigger (`POST /admin/retrain`), runs a background pipeline that:
  1. Queries all user reports from the database
  2. Appends them as new labeled training rows to the master CSV dataset
  3. Executes a full XGBoost + MLP Ensemble retraining job
  4. Atomically hot-reloads the new `xgboost_mlp_model.pkl` into the running server’s memory
- Prevents model drift by making the system’s intelligence adaptive to emerging threats

---
#### Objective 8 — Deliver a Professional SOC Dashboard
Build a **React-based Security Operations Center interface** (Vite + TailwindCSS) that provides:
- Aggregate real-time statistics: total scans, phishing count, suspicious count, safe count
- A **7-day security score progression chart** (Recharts line graph) showing the organization’s net threat posture over time
- A **live, paginated detection log table** with per-URL feature vectors
- A **global search feature** enabling analysts to query the full historical URL log
- Model performance KPIs: accuracy percentage and false positive rate
- All data served from the FastAPI backend via RESTful JSON endpoints

---
### B.2 Secondary Objectives
1. **Deploy the complete system using Docker Compose** — Containerize all four components (PostgreSQL, Redis, FastAPI backend, Nginx/React frontend) with health checks, environment variable injection, and inter-service communication, making the project reproducible on any machine with a single command.
2. **Implement performance optimizations at every layer** — Redis caching to avoid redundant ML inference; in-memory Tranco whitelist set for O(1) domain lookup; async blockchain logging to eliminate network-latency bottlenecks.
3. **Ensure graceful degradation** — Each external dependency (Google Safe Browsing API, WHOIS server, blockchain node) must fail-open: if the service is unavailable, the system falls back to the next internal layer without crashing or returning errors to the user.
4. **Design for extensibility** — The architecture must allow future integration of additional threat intelligence feeds (PhishTank, VirusTotal), additional ML models (XGBoost, neural networks), RBAC authentication between analyst roles, and geographic IP threat mapping without requiring core system redesign.
5. **Produce a production-ready codebase** — Follow software engineering best practices: modular code structure, environment variable configuration (`.env`), Dockerfile definitions, separate concerns across `schemas.py`, `models.py`, `database.py`, and individual ML module files.

---
### B.3 Objective Summary Table

| # | Objective | Component | Success Metric |
| :--- | :--- | :--- | :--- |
| 1 | Browser-native real-time detection | Chrome Extension | 8+ features extracted per page; <500ms response |
| 2 | Multi-layer AI pipeline | FastAPI backend | 5-tier cascade; single unified confidence score |
| 3 | Accurate ML model | XGBoost + MLP Ensemble (scikit-learn) | ≥90% accuracy; <5% false positive rate |
| 4 | Lexical heuristics engine | `heuristics.py` | Typosquatting, entropy, keyword, brand subdomain |
| 5 | Visual zero-day detection | `vision_engine.py` (OpenCV/SSIM) | ≥80% SSIM threshold for UI clone detection |
| 6 | Immutable blockchain audit | `ThreatLog.sol` (Ethereum Sepolia Testnet/Solidity) | On-chain log per Phishing verdict; async call |
| 7 | MLOps retraining pipeline | `retrain_pipeline.py` | Hot-reload new model; zero server downtime |
| 8 | SOC Dashboard | React + Vite + Recharts | Live stats, 7-day chart, log table, search |
| S1 | Docker containerization | `docker-compose.yml` | Single command full-stack launch |
| S2 | Performance optimization | Redis + Tranco + async | O(1) whitelist; cached results in <50ms |
| S3 | Graceful degradation | All external API calls | System functions if any external API is down |
| S4 | Extensibility | Modular architecture | Core system unchanged when adding new layers |
| S5 | Production-ready code | All modules | Env config, separation of concerns, Dockerfiles |

---
### B.4 Statement of Objectives (Condensed, Suitable for Report Abstract)
> **The objective of this project is to design, implement, and evaluate PhishGuard SOC — a multi-component, production-grade phishing detection system that achieves real-time URL threat analysis through a five-tier cascading intelligence pipeline. Specifically, the project aims to: (1) develop a Chrome browser extension capable of extracting live DOM-level features from active webpages; (2) train a XGBoost + MLP Ensemble ML classifier on a merged dataset of 50,000+ verified phishing vectors; (3) implement an advanced lexical heuristics module performing entropy analysis, typosquatting detection, and keyword scoring; (4) build a Visual AI pipeline using OpenCV SSIM to detect zero-day UI cloning attacks; (5) deploy an Ethereum smart contract providing a tamper-proof, blockchain-backed audit trail of confirmed phishing events; (6) build a continuous MLOps retraining pipeline enabling adaptive model improvement from user feedback; and (7) deliver a professional Security Operations Center dashboard for centralized organizational threat visibility — all deployed as a containerized, production-ready system via Docker Compose.**
