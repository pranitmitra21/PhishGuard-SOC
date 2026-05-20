// content.js
// Extracts features from the current page

function getFeatures() {
    const url = window.location.href;
    const hostname = window.location.hostname;

    // Feature extraction logic
    const urlLength = url.length;
    const hasAtSymbol = url.includes('@');

    // Count subdomains (e.g. www.google.com -> 3 parts -> 2 dots)
    // simplistic counting strategy
    const ipPattern = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
    let numSubdomains = 0;
    if (!ipPattern.test(hostname)) {
        numSubdomains = hostname.split('.').length - 2; // e.g. a.b.com -> 3 parts -> 1 subdomain
        if (numSubdomains < 0) numSubdomains = 0;
    }

    const isHttps = window.location.protocol === 'https:';

    // Check for password inputs on the page
    const passwordInputs = document.querySelectorAll('input[type="password"]');
    const hasPasswordField = passwordInputs.length > 0;

    // Simple DOM checks
    let suspiciousElements = 0;
    let hasCrossOriginForm = false;

    // Deep HTML Analysis: Check if password forms submit to an external domain
    if (hasPasswordField) {
        passwordInputs.forEach(input => {
            const form = input.closest('form');
            if (form && form.action) {
                try {
                    const actionUrl = new URL(form.action, url);
                    // Compare root domains
                    const hostParts = hostname.split('.');
                    const actionParts = actionUrl.hostname.split('.');
                    const hostRoot = hostParts.slice(-2).join('.');
                    const actionRoot = actionParts.slice(-2).join('.');
                    
                    if (hostRoot !== actionRoot) {
                        hasCrossOriginForm = true;
                        suspiciousElements += 5; // Severe penalty
                    }
                } catch (e) {
                    // Invalid action URL, potentially suspicious
                    suspiciousElements += 1;
                }
            }
        });
    }

    // Check if passwords are being sent over non-HTTPS
    if (!isHttps && hasPasswordField) {
        suspiciousElements += 2;
    }

    // Check for weird invisible iframes (common in phishing)
    const iframes = document.querySelectorAll('iframe');
    iframes.forEach(iframe => {
        if (iframe.style.display === 'none' || iframe.style.visibility === 'hidden' || iframe.width === '0' || iframe.height === '0') {
            suspiciousElements++;
        }
    });

    const navEntry = performance.getEntriesByType("navigation")[0];
    const numRedirects = navEntry ? navEntry.redirectCount : 0;

    return {
        url: url,
        url_length: urlLength,
        has_at_symbol: hasAtSymbol,
        num_subdomains: numSubdomains,
        is_https: isHttps,
        num_redirects: numRedirects,
        suspicious_dom_elements: suspiciousElements,
        has_password_field: hasPasswordField,
        has_cross_origin_form: hasCrossOriginForm
    };
}

/**
 * FAST LOCAL HEURISTIC — runs entirely in the browser with zero network calls.
 * Checks the same high-signal features the backend heuristics use.
 * Returns true if the page looks suspicious enough to show a pending overlay.
 * This gives the user visual feedback in ~300ms instead of waiting 7s for the backend.
 */
function quickSuspiciousCheck(features) {
    const url = features.url.toLowerCase();
    const SUSPICIOUS_KEYWORDS = ['login', 'verify', 'secure', 'update', 'account', 'banking', 'wallet', 'auth', 'confirm', 'recover', 'billing'];
    const keywordHits = SUSPICIOUS_KEYWORDS.filter(kw => url.includes(kw)).length;

    // Trigger pre-warning if any of these high-confidence signals fire:
    if (features.has_cross_origin_form) return true;           // Password sent to external domain
    if (features.has_at_symbol) return true;                   // @ in URL — classic phishing trick
    if (!features.is_https && features.has_password_field) return true; // HTTP login form
    if (features.num_subdomains >= 3) return true;             // Excessive subdomains
    if (features.url_length > 120 && keywordHits >= 2) return true; // Long URL + keywords
    if (features.suspicious_dom_elements >= 3) return true;   // Many DOM red flags

    return false;
}

// Send features back via messaging or handle overlay injection
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "extract_features") {
        const features = getFeatures();
        // Attach a fast local pre-check result so background.js can decide
        // whether to show the pending overlay before the API responds.
        features._quick_suspicious = quickSuspiciousCheck(features);
        sendResponse(features);
    } else if (request.action === "inject_pending_overlay") {
        injectPendingOverlay();
    } else if (request.action === "inject_overlay") {
        injectWarningOverlay(request.data);
    } else if (request.action === "update_overlay") {
        updateOverlay(request.data);
    } else if (request.action === "remove_overlay") {
        const existing = document.getElementById('phishguard-xai-overlay');
        if (existing) {
            existing.remove();
            document.body.style.overflow = 'auto';
        }
    }
});

/**
 * PHASE 1 — Pending overlay: shown INSTANTLY when quick heuristics flag the page.
 * Blocks the page with an amber scanning state while the backend processes.
 * Replaced by updateOverlay() when the final verdict arrives.
 */
function injectPendingOverlay() {
    if (document.getElementById('phishguard-xai-overlay')) return; // already showing

    const overlay = document.createElement('div');
    overlay.id = 'phishguard-xai-overlay';
    overlay.setAttribute('data-state', 'pending');
    overlay.style.cssText = `
        position: fixed; top: 0; left: 0; width: 100vw; height: 100vh;
        background: rgba(10, 5, 0, 0.92); z-index: 2147483647;
        font-family: 'Courier New', Courier, monospace; color: white;
        display: flex; flex-direction: column; align-items: center; justify-content: center;
        backdrop-filter: blur(8px);
    `;
    overlay.innerHTML = `
        <div style="border: 2px solid #ffb000; padding: 40px; text-align: center; max-width: 700px;
                    background: #0a0500; box-shadow: 0 0 30px rgba(255,176,0,0.4);">
            <h1 style="color: #ffb000; font-size: 2.2rem; margin-top: 0; letter-spacing: 2px;">
                ⚠ PHISHGUARD AI — SCANNING
            </h1>
            <p style="color: #ccc; font-size: 1rem; margin: 10px 0 20px;">
                Suspicious signals detected. Running full AI + Blockchain analysis...
            </p>
            <div style="display: flex; align-items: center; justify-content: center; gap: 10px;">
                <div id="pg-spinner" style="
                    width: 20px; height: 20px; border: 3px solid rgba(255,176,0,0.3);
                    border-top-color: #ffb000; border-radius: 50%;
                    animation: pg-spin 0.8s linear infinite;
                "></div>
                <span style="color: #ffb000; font-size: 1.1rem;">Analysing threat vectors...</span>
            </div>
            <style>@keyframes pg-spin { to { transform: rotate(360deg); } }</style>
            <br><br>
            <button id="phishguard-proceed" style="
                background: none; border: 1px solid #555; color: #666;
                padding: 8px 18px; cursor: pointer; font-size: 0.85rem;
            ">Proceed without waiting (Not Recommended)</button>
        </div>
    `;
    document.body.appendChild(overlay);
    document.body.style.overflow = 'hidden';
    document.getElementById('phishguard-proceed').addEventListener('click', () => {
        overlay.remove();
        document.body.style.overflow = 'auto';
    });
}

/**
 * PHASE 2 — Update or inject the final verdict overlay.
 * If a pending overlay is showing, replaces it with the definitive result.
 * If no overlay is showing, injects it fresh (for auto-scan results).
 */
function updateOverlay(aiData) {
    const existing = document.getElementById('phishguard-xai-overlay');
    if (existing) {
        // Only upgrade if we were in pending state or the verdict is worse
        existing.remove();
        document.body.style.overflow = 'auto';
    }
    // Only inject the final overlay if the result is Phishing or Suspicious
    if (aiData.status === 'Safe') return;
    injectWarningOverlay(aiData);
}

/**
 * FULL WARNING OVERLAY — shows XAI threat report with final verdict.
 */
function injectWarningOverlay(aiData) {
    if (document.getElementById('phishguard-xai-overlay')) return;

    const overlay = document.createElement('div');
    overlay.id = 'phishguard-xai-overlay';
    
    // Cyberpunk-style red warning styling
    overlay.style.cssText = `
        position: fixed; top: 0; left: 0; width: 100vw; height: 100vh;
        background: rgba(20, 0, 0, 0.95); z-index: 2147483647;
        font-family: 'Courier New', Courier, monospace; color: white;
        display: flex; flex-direction: column; align-items: center; justify-content: center;
        backdrop-filter: blur(10px);
    `;

    // Process reasons efficiently
    let reasonsHtml = '';
    if (aiData.message) {
        let reasons = aiData.message.split(' | ');
        reasons.forEach(r => {
            if(r.trim() && !r.includes('multi-layer engine') && !r.includes('Scanned previously.')) {
                reasonsHtml += `<li style="color: #ffb000; margin-bottom: 10px; font-size: 1.2rem;">⚠️ ${r}</li>`;
            }
        });
    }

    if (!reasonsHtml) {
        reasonsHtml = `<li style="color: #ffb000; font-size: 1.2rem;">⚠️ Machine Learning Model Confidence: ${aiData.confidence.toFixed(2)}%</li>`;
    }

    const threatLevel = aiData.status.toUpperCase();
    const borderColor = threatLevel === 'PHISHING' ? '#ff003c' : '#ffb000';

    overlay.innerHTML = `
        <div style="border: 2px solid ${borderColor}; padding: 40px; text-align: center; max-width: 800px; background: #000; box-shadow: 0 0 30px ${borderColor};">
            <h1 style="color: ${borderColor}; font-size: 3rem; margin-top: 0;">CRITICAL SECURITY ALERT: ${threatLevel}</h1>
            <h2 style="color: #fff;">PhishGuard AI has blocked this page.</h2>
            <br>
            <div style="text-align: left; background: #111; padding: 20px; border-left: 4px solid #ffb000;">
                <h3 style="color: #fff; margin-top: 0;">Explainable AI Threat Intel Report:</h3>
                <ul style="list-style-type: none; padding-left: 0;">
                    ${reasonsHtml}
                </ul>
            </div>
            <br><br>
            <button id="phishguard-proceed" style="background: none; border: 1px solid #555; color: #888; padding: 10px 20px; cursor: pointer; text-decoration: underline;">I understand the risks, proceed anyway (Not Recommended)</button>
        </div>
    `;

    document.body.appendChild(overlay);
    document.body.style.overflow = 'hidden'; // Prevent scrolling

    document.getElementById('phishguard-proceed').addEventListener('click', () => {
        overlay.remove();
        document.body.style.overflow = 'auto';
    });
}
