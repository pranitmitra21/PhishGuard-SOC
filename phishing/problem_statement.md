# PhishGuard SOC — Detailed Problem Statement

---

## 1. Background & The Global Threat Landscape

Phishing is the single most common form of cybercrime in the world
today. It is a socially engineered attack in which a malicious actor
creates a fraudulent website or URL that impersonates a legitimate one —
such as a bank, e-commerce portal, or email provider — to deceive users
into surrendering sensitive information such as passwords, credit card
numbers, or authentication tokens.

According to industry reports: - **Over 3.4 billion phishing
emails** are sent every single day globally. - Phishing attacks
account for **more than 36% of all data breaches** (Verizon
DBIR). - The **average financial loss per phishing
incident** for organizations has crossed **$4.9 million
USD**. - A new phishing website is created approximately
**every 20 seconds**, making reactive blocklists inadequate
by design. - **90% of all cyberattacks begin with a phishing
attempt**, making it the primary attack vector across
industries.

Despite decades of security research, phishing remains devastatingly
effective because it targets the weakest link in any security system:
the **human user**. Users cannot be expected to manually
inspect every URL they visit for subtle deception — especially when
attackers use techniques like typosquatting (`paypa1.com`),
subdomain injection (`paypal.secure-login.xyz`), and visual
UI cloning that are virtually invisible to the human eye.

---

## 2. Core Problems Being Solved

### Problem 1 — No Real-Time Browser-Level Protection

**The Gap**: Existing antivirus software and firewalls
operate at the network layer and are installed on devices. They cannot
inspect the rich contextual signals available *inside a live
webpage* — such as the structure of HTML forms, whether a password
field submits to an external domain, or the presence of hidden
iframes.

**The Consequence**: A user visiting a visually
identical fake banking page in Chrome gets no warning. By the time the
network-level tool detects an anomaly (if it does), the user’s
credentials may already have been submitted.

**PhishGuard’s Answer**: A **Chrome Extension
(Manifest V3)** runs a deep DOM feature extractor inside every
open webpage. It captures: - Whether the page hosts a password form that
submits to a **cross-origin domain** (Zero-Click Credential
Theft) - The presence of hidden or zero-dimension
`<iframe>` elements (classic click-jacking and data
exfiltration technique) - URL-level signals like subdomain count,
`@` symbol presence, and HTTPS status — all extracted live
from the active browser tab

---

### Problem 2 — Static Blocklists Are Reactive, Not Proactive

**The Gap**: The most widely used defenses — browser
built-in blocklists, Google Safe Browsing, and antivirus URL databases —
are **reactive systems**. A URL must first be reported,
verified, and then added to the blocklist. This process typically takes
**24 to 72 hours**.

**The Consequence**: Phishing campaigns are designed to
be ephemeral. Attackers launch a site, harvest credentials for 48 hours,
and then abandon the domain — often before any blocklist is updated.
Studies show that over **60% of phishing sites are active for less
than 24 hours**.

**PhishGuard’s Answer**: Rather than relying solely on
blocklists, PhishGuard uses a **trained Machine Learning model
(XGBoost + Multi-Layer Perceptron (MLP) Ensemble)** capable of analyzing a URL it has
never seen before and predicting its threat probability. The model was
trained on a **50,000+ verified phishing vectors dataset** of real phishing and
benign URLs, allowing it to generalize to brand-new, previously unseen
attack patterns.

---

### Problem 3 — URL String Analysis Alone Is Insufficient

**The Gap**: Even ML-based URL classifiers that analyze
URL strings are vulnerable to **zero-day visual phishing**
— attacks where an adversary compromises a legitimate, trusted domain
(or uses a brand-new domain with a clean reputation) and hosts a
pixel-perfect clone of a bank or corporate login page. The URL passes
all string-based checks because the domain itself is not malicious.

**The Consequence**: A user visits
`accounts.verylegit-corp.com/microsoft-login` — the URL is
HTTPS, has no suspicious subdomains, has no typosquatting, and passes
every lexical check. But the page is a cloned Microsoft login page.

**PhishGuard’s Answer**: When the Chrome extension
detects a **password form on a page**, it captures a
screenshot of the visible page and sends it to the backend
`/vision-scan` endpoint. The **Visual AI
Engine** uses **OpenCV** and the **SSIM
(Structural Similarity Index)** algorithm to compare the live
screenshot against a library of known brand login pages. If any match
exceeds 80% visual similarity, the page is flagged as a UI clone
regardless of URL analysis results.

---

### Problem 4 — Detection Without Explanation Is Unacceptable

**The Gap**: Many security tools give a binary verdict:
“safe” or “dangerous.” They provide no explanation to the user about
*why* a site was flagged. This creates two serious problems: 1.
**User distrust**: Users who don’t understand the reason
are more likely to dismiss the warning and proceed anyway. 2.
**High false-positive frustration**: If a legitimate site
is flagged with no reason given, users lose confidence in the tool
entirely.

This lack of transparency is known as the **Black Box AI
Problem** in cybersecurity.

**PhishGuard’s Answer**: Every detection verdict
includes a structured **Explainable AI (XAI) report** — a
plain-English list of exactly which signals triggered the alert:

> *“⚠️ Typosquatting detected (mimicking ‘paypal’)”*  
> *“⚠️ Brand name ‘google’ used deceptively in subdomain”*  
> *“⚠️ Zero-Click Theft: Password form submits to external tracking
> domain!”*  
> *“⚠️ High hostname entropy (4.73) — possible bot-generated
> domain”*

These reasons are displayed in the browser extension popup and also
injected as a **full-screen blocking overlay** directly
onto the suspicious webpage, mirroring how enterprise SIEM (Security
Information and Event Management) tools present structured threat
intelligence.

---

### Problem 5 — No Tamper-Proof Record of Phishing Events

**The Gap**: When a phishing attack is detected and
logged, the log record is typically stored in a centralized SQL
database. Centralized records are: - **Mutable** — a
compromised admin or insider threat can delete or modify them. -
**Single points of failure** — if the server is lost, so is
the evidence. - **Non-auditable** — there is no way for an
external party to independently verify when and what was logged.

For cybercrime prosecutions, insurance claims, and regulatory
compliance (GDPR, HIPAA), a verifiable, immutable audit trail is not
optional — it is legally and procedurally essential.

**PhishGuard’s Answer**: Every URL confirmed as Phishing
is logged asynchronously to an **Ethereum smart contract**
(`ThreatLog.sol` deployed on a Ethereum Sepolia Testnet). The
contract stores: - The **SHA256 hash of the URL**
(privacy-preserving — the actual URL is not on-chain) - An **IPFS
content identifier (CID)** pointing to the full evidence package
(DOM features, scan metadata) - An on-chain **timestamp**
and the **reporter’s Ethereum address**

Once written, this record **cannot be altered or deleted by
anyone** — including system administrators. The blockchain’s
immutability transforms the threat log from a mutable database record
into a legally defensible, cryptographically verified audit trail.

---

### Problem 6 — Security Teams Have No Centralized Visibility

**The Gap**: End users only see a per-page result. But
an organization’s **Security Operations Center (SOC)**
needs a bird’s-eye view: - How many phishing attempts were blocked
today? - Is the attack rate increasing over time? - Which specific URLs
were targeted and when? - What is the model’s current accuracy and false
positive rate?

Without centralized threat visualization, security analysts are
flying blind and cannot detect coordinated, large-scale phishing
campaigns targeting an organization.

**PhishGuard’s Answer**: A dedicated **React-based
SOC Dashboard** provides security analysts with: - Real-time
threat counts (Phishing / Suspicious / Safe / Total) - A **7-day
Security Score trend chart** showing the organization’s threat
posture over time - A **live, scrollable detection log**
with full feature vectors per scan - A **global URL
search** capability across all historical scan data - Model
performance metrics (accuracy, false positive rate)

This transforms PhishGuard from a personal browser tool into a
centralized enterprise threat monitoring platform.

---

### Problem 7 — ML Models Become Stale Over Time (Model Drift)

**The Gap**: Phishing techniques evolve constantly. A
model trained on data from 6 months ago may perform poorly against
today’s attacks because: - New phishing keywords emerge (e.g.,
“covid-relief”, “ukraine-aid”, “AI-verification”) - New attack patterns
appear (QR code phishing, SMS phishing redirects) - The distribution of
phishing vs. safe URLs in the real world shifts

This problem is called **Model Drift** — and it is the
Achilles’ heel of static ML-based security systems.

**PhishGuard’s Answer**: An **automated MLOps
Retraining Pipeline** solves this at its root: 1. Users can
report false negatives (missed phishing) via a dedicated
`/report` endpoint. 2. Reported URLs are stored in the
PostgreSQL database with label `User_Reported_Phishing`. 3.
When an admin triggers `/admin/retrain`, a **background
task** collects all reports, appends them as new training samples
to the master dataset CSV, runs a **full XGBoost + MLP Ensemble
retraining**, and **hot-reloads the new model file into
memory** — all without restarting the server or causing
downtime.

The system continuously improves its own accuracy from real-world
feedback — a key characteristic of production-grade enterprise ML
systems.

---

## 3. Why Existing Solutions Are Inadequate

| Existing Solution | What It Misses |
| --- | --- |
| **Google Safe Browsing** | Reactive blocklist — misses attacks in first 24–72 hrs; no DOM analysis |
| **Browser built-in warnings** | Simple heuristics only; no ML, no visual analysis, no XAI |
| **Antivirus software** | Network-level only; no in-page DOM inspection; no blockchain audit |
| **PhishTank / OpenPhish** | Community-reported databases — days-old data; no real-time inference |
| **Academic ML classifiers** | URL-string only; no live DOM features; no retraining; no UI |
| **Enterprise SIEM tools** | Expensive, complex, no browser-native integration; no visual AI |

---

## 4. Scope and Boundaries

**In Scope:** - Detection of phishing via URL
heuristics, ML inference, and visual AI - Real-time detection at the
browser level for every page visited - Blockchain-based immutable
logging for confirmed threats - SOC dashboard for organizational threat
monitoring - Automated model retraining from user feedback

**Out of Scope:** - Email phishing / attachment scanning
- Detection of phishing via phone calls (vishing) or SMS (smishing) -
Real-time geographic IP threat mapping (planned feature) - Full RBAC
authentication between analyst roles (planned feature) - Deployment to a
public cloud (currently local Docker setup)

---

## 5. Formal Problem Statement

> **Current web users and organizational security teams lack a
> unified, real-time defense system capable of detecting phishing attacks
> at the browser level using multiple converging intelligence layers.
> Existing solutions are either reactive blocklists that fail within the
> first 24–72 hours of a campaign, or isolated ML classifiers that analyze
> only URL strings and provide no explainability, no visual detection
> capability, no tamper-proof incident logging, and no mechanism for
> continuous self-improvement. There exists a critical need for an
> end-to-end, browser-native phishing detection platform that integrates
> live DOM feature extraction, multi-layer AI inference (machine learning,
> lexical heuristics, and computer vision), Explainable AI for
> human-readable threat reporting, a blockchain-backed immutable audit
> trail, and an automated MLOps retraining pipeline — all visible through
> a centralized SOC dashboard — to provide proactive, adaptive, and
> trustworthy protection against one of the most prevalent and damaging
> forms of cybercrime.**

---

## 6. Research Questions Addressed

1. Can a multi-layer detection engine (ML + Heuristics + Vision +
   Threat Intel) achieve higher accuracy and lower false positives than any
   single-layer approach?
2. Can live DOM features extracted directly from a browser page
   significantly improve phishing detection beyond URL-string analysis
   alone?
3. Can visual SSIM-based screenshot comparison effectively identify
   zero-day UI clone attacks that evade URL-based systems?
4. Can a blockchain smart contract serve as a practical, tamper-proof
   incident logging system within a real-time threat detection
   pipeline?
5. Can an online MLOps retraining loop prevent model drift and sustain
   detection accuracy as phishing techniques evolve over time?