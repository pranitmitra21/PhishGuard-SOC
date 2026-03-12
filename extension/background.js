// background.js

const API_URL = "http://localhost:8000/detect";

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "analyze_current_tab") {
        chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
            if (!tabs || tabs.length === 0) return;
            const activeTab = tabs[0];
            const tabId = activeTab.id;

            // Check if restricted page before injecting
            if (activeTab.url && (activeTab.url.startsWith("chrome://") || activeTab.url.startsWith("chrome-extension://") || activeTab.url.startsWith("edge://"))) {
                sendResponse({ error: "restricted_page" });
                return;
            }

            // Attempt to get features from the content script
            chrome.tabs.sendMessage(tabId, { action: "extract_features" }, function (features) {
                if (chrome.runtime.lastError) {
                    // Script not injected yet, inject it manually
                    chrome.scripting.executeScript({
                        target: { tabId: tabId },
                        files: ['content.js']
                    }).then(() => {
                        // After injection, try sending the message again
                        chrome.tabs.sendMessage(tabId, { action: "extract_features" }, function (newFeatures) {
                            if (chrome.runtime.lastError) {
                                console.error("Still could not communicate with content script.");
                                sendResponse({ error: "reload_required" });
                                return;
                            }
                            handleFeatures(newFeatures, tabId, sendResponse);
                        });
                    }).catch(err => {
                        console.error("Script injection failed: ", err);
                        sendResponse({ error: "injection_failed" });
                    });
                    return true;
                }
                handleFeatures(features, tabId, sendResponse);
            });

            function handleFeatures(features, tabId, sendResponse) {
                if (features) {
                    fetch(API_URL, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify(features)
                    })
                        .then(response => response.json())
                        .then(data => {
                            sendResponse(data);
                        })
                        .catch(error => {
                            console.error("API Error: ", error);
                            sendResponse({ error: "api_error" });
                        });
                } else {
                    sendResponse({ error: "no_features" });
                }
            }
        });

        return true; // Required to use sendResponse asynchronously
    }
});
