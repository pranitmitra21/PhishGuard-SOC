// background.js - PhishGuard SOC v2.0

const API_URL = "http://127.0.0.1:8000/detect";

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "analyze_current_tab") {

        chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
            if (!tabs || tabs.length === 0) {
                sendResponse({ error: "no_tab" });
                return;
            }

            const activeTab = tabs[0];
            const tabId = activeTab.id;

            // Block restricted pages immediately
            if (
                activeTab.url &&
                (
                    activeTab.url.startsWith("chrome://") ||
                    activeTab.url.startsWith("chrome-extension://") ||
                    activeTab.url.startsWith("edge://") ||
                    activeTab.url.startsWith("about:")
                )
            ) {
                sendResponse({ error: "restricted_page" });
                return;
            }

            // Try to get features from an already-injected content script
            chrome.tabs.sendMessage(tabId, { action: "extract_features" }, function (features) {
                if (chrome.runtime.lastError || !features) {
                    // Content script not yet active — inject it first
                    chrome.scripting.executeScript({
                        target: { tabId: tabId },
                        files: ['content.js']
                    }).then(() => {
                        // Small delay to ensure the script registers its listener
                        setTimeout(() => {
                            chrome.tabs.sendMessage(tabId, { action: "extract_features" }, function (newFeatures) {
                                if (chrome.runtime.lastError || !newFeatures) {
                                    sendResponse({ error: "reload_required" });
                                    return;
                                }
                                callAPI(newFeatures, sendResponse);
                            });
                        }, 200);
                    }).catch(err => {
                        console.error("Script injection failed:", err);
                        sendResponse({ error: "reload_required" });
                    });
                } else {
                    callAPI(features, sendResponse);
                }
            });
        });

        return true; // Keep message channel open for async sendResponse
    }
});

function callAPI(features, sendResponse) {
    fetch(API_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(features)
    })
    .then(response => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json();
    })
    .then(data => {
        data.url = features.url;
        data.features = features;

        // Visual AI Upgrade: If we detect a password field and it's not a known safe domain,
        // let's run a screenshot similarity check against known clones.
        if (features.has_password_field && data.status !== "Safe" && !data.is_whitelisted) {
            chrome.tabs.captureVisibleTab(null, {format: "jpeg", quality: 40}, function(dataUrl) {
                if(chrome.runtime.lastError || !dataUrl) {
                    sendResponse(data); 
                    return;
                }
                fetch("http://127.0.0.1:8000/vision-scan", {
                    method: "POST",
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url: features.url, screenshot_base64: dataUrl })
                })
                .then(r => r.json())
                .then(visionData => {
                    if (visionData.is_clone) {
                        data.status = "Phishing";
                        data.confidence = 99.9;
                        data.message = (data.message || "") + " | CV Alert: " + visionData.message;
                    }
                    sendResponse(data);
                })
                .catch(err => {
                    sendResponse(data);
                });
            });
        } else {
            sendResponse(data);
        }
    })
    .catch(error => {
        console.error("API Error:", error);
        sendResponse({ error: "api_error" });
    });
}

// Auto-scan logic: runs securely on page load without needing a popup click!
function autoScanTab(tabId, tabUrl) {
    if (tabUrl.startsWith("chrome") || tabUrl.startsWith("about:") || tabUrl.startsWith("edge:") || tabUrl.startsWith("file:")) return;
    
    // We send a lightweight extraction ping
    chrome.tabs.sendMessage(tabId, { action: "extract_features" }, function(features) {
        if (chrome.runtime.lastError || !features) {
            // Need to inject content.js if it hasn't loaded 
            chrome.scripting.executeScript({ target: { tabId: tabId }, files: ['content.js'] }).then(() => {
                setTimeout(() => {
                    chrome.tabs.sendMessage(tabId, { action: "extract_features" }, function(newFeatures) {
                        if(newFeatures && !chrome.runtime.lastError) processAndInject(newFeatures, tabId);
                    });
                }, 200);
            }).catch(e => console.error("Background injection err:", e));
        } else {
            processAndInject(features, tabId);
        }
    });
}

function processAndInject(features, tabId) {
    callAPI(features, (data) => {
        if (data && (data.status === "Phishing" || data.status === "Suspicious")) {
            chrome.tabs.sendMessage(tabId, { action: "inject_overlay", data: data });
        }
    });
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    // We trigger the scan once the DOM completes
    if (changeInfo.status === 'complete' && tab.url) {
        autoScanTab(tabId, tab.url);
    }
});
