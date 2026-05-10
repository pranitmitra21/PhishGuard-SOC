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

    return {
        url: url,
        url_length: urlLength,
        has_at_symbol: hasAtSymbol,
        num_subdomains: numSubdomains,
        is_https: isHttps,
        num_redirects: 0, // In manifest v3, we'd have to track in background or history
        suspicious_dom_elements: suspiciousElements,
        has_password_field: hasPasswordField,
        has_cross_origin_form: hasCrossOriginForm
    };
}

// Send features back via messaging or handle overlay injection
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "extract_features") {
        sendResponse(getFeatures());
    } else if (request.action === "inject_overlay") {
        injectWarningOverlay(request.data);
    }
});

function injectWarningOverlay(aiData) {
    if (document.getElementById("phishguard-xai-overlay")) return;

    const overlay = document.createElement("div");
    overlay.id = "phishguard-xai-overlay";
    
    // Cyberpunk-style red warning styling
    overlay.style.cssText = `
        position: fixed; top: 0; left: 0; width: 100vw; height: 100vh;
        background: rgba(20, 0, 0, 0.95); z-index: 2147483647;
        font-family: 'Courier New', Courier, monospace; color: white;
        display: flex; flex-direction: column; align-items: center; justify-content: center;
        backdrop-filter: blur(10px);
    `;

    // Process reasons efficiently
    let reasonsHtml = "";
    if (aiData.message) {
        let reasons = aiData.message.split(" | ");
        reasons.forEach(r => {
            if(r.trim() && !r.includes("multi-layer engine")) {
                reasonsHtml += `<li style="color: #ffb000; margin-bottom: 10px; font-size: 1.2rem;">⚠️ ${r}</li>`;
            }
        });
    }

    if (!reasonsHtml) {
        reasonsHtml = `<li style="color: #ffb000; font-size: 1.2rem;">⚠️ Machine Learning Model Confidence: ${aiData.confidence.toFixed(2)}%</li>`;
    }

    const threatLevel = aiData.status.toUpperCase();
    const borderColor = threatLevel === "PHISHING" ? "#ff003c" : "#ffb000";

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
    document.body.style.overflow = "hidden"; // Prevent scrolling

    document.getElementById("phishguard-proceed").addEventListener("click", () => {
        overlay.remove();
        document.body.style.overflow = "auto";
    });
}
