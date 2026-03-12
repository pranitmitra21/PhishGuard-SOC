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

    // Simple DOM checks
    let suspiciousElements = 0;

    // Check if passwords are being sent over non-HTTPS
    if (!isHttps && document.querySelectorAll('input[type="password"]').length > 0) {
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
        suspicious_dom_elements: suspiciousElements
    };
}

// Send features back via messaging
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "extract_features") {
        sendResponse(getFeatures());
    }
});
