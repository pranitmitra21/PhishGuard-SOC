// background.js - PhishGuard SOC v2.0

const API_URL = "http://127.0.0.1:8000/api/detect";

// Unique session ID stored in memory to identify the current active browser instance.
// Using chrome.storage.session ensures it persists across service worker wake/sleep cycles
// but is completely wiped when the Chrome browser is closed.
async function getSessionId() {
    const data = await chrome.storage.session.get('sessionId');
    if (data.sessionId) return data.sessionId;
    const newId = crypto.randomUUID();
    await chrome.storage.session.set({ sessionId: newId });
    return newId;
}

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
                    activeTab.url.startsWith("about:") ||
                    activeTab.url.startsWith("file://")
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

async function callAPI(features, sendResponse) {
    features.session_id = await getSessionId(); // Attach the session ID to every request
    
    // Get optional auth token for multi-tenancy isolation safely
    const soc_token = await new Promise((resolve) => {
        chrome.storage.local.get(['soc_token'], (res) => {
            resolve(res.soc_token);
        });
    });
    
    const headers = { 'Content-Type': 'application/json' };
    if (soc_token) {
        headers['Authorization'] = `Bearer ${soc_token}`;
    }

    fetch(API_URL, {
        method: 'POST',
        headers: headers,
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
                fetch("http://127.0.0.1:8000/api/vision-scan", {
                    method: "POST",
                    headers: headers,
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
    // Skip internal, extension, and file pages
    if (!tabUrl || 
        tabUrl.startsWith("chrome") || 
        tabUrl.startsWith("about:") || 
        tabUrl.startsWith("edge:") || 
        tabUrl.startsWith("file:") ||
        tabUrl.startsWith("chrome-extension:")) return;

    // Wait 200ms for the content script listener to fully register.
    // Content.js is injected by the manifest so its onMessage listener is ready
    // almost immediately after DOM load — 200ms is a safe margin (was 600ms).
    setTimeout(() => {
        chrome.tabs.sendMessage(tabId, { action: "extract_features" }, function(features) {
            if (chrome.runtime.lastError) {
                // Content script may still not be ready (e.g. page blocked scripting)
                // Silently skip — user can still manually scan via popup
                return;
            }
            if (features) {
                processAndInject(features, tabId);
            }
        });
    }, 200);
}

function processAndInject(features, tabId) {
    // PHASE 1: If quick local check flags the page, show amber scanning overlay IMMEDIATELY
    if (features._quick_suspicious) {
        chrome.tabs.get(tabId, (tab) => {
            if (!chrome.runtime.lastError && tab) {
                chrome.tabs.sendMessage(tabId, { action: "inject_pending_overlay" });
            }
        });
    }

    callAPI(features, (data) => {
        if (data && data.error) {
            // Fail open if the backend server is down, so we don't break the user's browsing experience
            chrome.tabs.get(tabId, (tab) => {
                if (chrome.runtime.lastError || !tab) return;
                // Add a small delay to ensure the pending overlay had time to render before we destroy it
                setTimeout(() => {
                    chrome.tabs.sendMessage(tabId, { action: "remove_overlay" });
                }, 100);
            });
            return;
        }

        if (data && (data.status === "Phishing" || data.status === "Suspicious")) {
            // Re-check tab still exists before injecting overlay
            chrome.tabs.get(tabId, (tab) => {
                if (chrome.runtime.lastError || !tab) return;
                // PHASE 2: Replace pending overlay with final verdict (or inject fresh)
                chrome.tabs.sendMessage(tabId, { action: "update_overlay", data: data });
            });
        } else if (data && data.status === "Safe") {
            // Remove any pending scanning overlay if the site turns out safe
            chrome.tabs.get(tabId, (tab) => {
                if (chrome.runtime.lastError || !tab) return;
                chrome.tabs.sendMessage(tabId, { action: "update_overlay", data: data });
            });
        }
    });
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    // Trigger auto-scan the moment DOM is fully loaded
    if (changeInfo.status === 'complete' && tab.url) {
        autoScanTab(tabId, tab.url);
    }
});

