document.addEventListener('DOMContentLoaded', function () {
    const statusText   = document.getElementById('status-badge');
    const statusIcon   = document.getElementById('status-icon');
    const confidenceText = document.getElementById('confidence-text');
    const confidenceBar  = document.getElementById('confidence-bar');
    const bcLogged     = document.getElementById('bc-logged');
    const loader       = document.getElementById('loader');
    const resultDiv    = document.getElementById('result');
    const errorDiv     = document.getElementById('error');
    const errorMsg     = document.getElementById('error-msg');
    const reanalyzeBtn = document.getElementById('reanalyze-btn');
    const reportBtn    = document.getElementById('report-btn');
    const dashboardBtn = document.getElementById('dashboard-btn');
    const connectionDot = document.getElementById('connection-dot');
    const authView     = document.getElementById('auth-view');
    const authSubmitBtn = document.getElementById('auth-submit-btn');
    const authError    = document.getElementById('auth-error');
    const authModeTitle = document.getElementById('auth-mode-title');
    
    // Auth UI Elements
    const tabLogin = document.getElementById('tab-login');
    const tabRegister = document.getElementById('tab-register');
    const registerFields = document.getElementById('register-fields');
    const authRole = document.getElementById('auth-role');
    const authWallet = document.getElementById('auth-wallet');
    const authPin = document.getElementById('auth-pin');
    
    let isRegisterMode = false;

    // Backend API base — works for both dev (8000) and docker (80 via /api proxy)
    const API_BASE = 'http://127.0.0.1:8000/api';

    // Accordion Logic
    const toggleDetails  = document.getElementById('toggle-details');
    const detailsContent = document.getElementById('details-content');
    if (toggleDetails) {
        toggleDetails.addEventListener('click', () => {
            detailsContent.classList.toggle('open');
            const icon = toggleDetails.querySelector('svg');
            if (icon) {
                icon.style.transform  = detailsContent.classList.contains('open') ? 'rotate(180deg)' : 'rotate(0deg)';
                icon.style.transition = 'transform 0.3s ease';
            }
        });
    }

    // SVG icons for each status
    const ICONS = {
        Safe:       `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>`,
        Suspicious: `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>`,
        Phishing:   `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"></polygon><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>`
    };

    // Cyberpunk color map matching the new CSS variables
    const STATUS_COLORS = {
        Safe:       { color: '#39ff14', shadow: 'rgba(57,255,20,0.5)',  border: 'rgba(57,255,20,0.5)'  },
        Suspicious: { color: '#ffb000', shadow: 'rgba(255,176,0,0.5)',  border: 'rgba(255,176,0,0.5)'  },
        Phishing:   { color: '#ff003c', shadow: 'rgba(255,0,60,0.5)',   border: 'rgba(255,0,60,0.5)'   }
    };

    function applyTheme(status) {
        const theme = STATUS_COLORS[status] || STATUS_COLORS.Safe;

        statusText.innerText = status.toUpperCase();
        statusText.style.color      = theme.color;
        statusText.style.textShadow = `0 0 15px ${theme.color}`;

        statusIcon.innerHTML   = ICONS[status] || ICONS.Safe;
        statusIcon.style.color        = theme.color;
        statusIcon.style.borderColor  = theme.border;
        statusIcon.style.boxShadow    = `0 0 15px ${theme.shadow}, inset 0 0 10px rgba(0,0,0,0.5)`;

        confidenceBar.style.background  = theme.color;
        confidenceBar.style.boxShadow   = `0 0 8px ${theme.shadow}`;

        // Update connection dot color
        if (connectionDot) {
            connectionDot.style.background = theme.color;
            connectionDot.style.boxShadow  = `0 0 8px ${theme.color}`;
        }
    }

    function analyze() {
        // Reset to loading state
        loader.classList.remove('hidden');
        resultDiv.classList.add('hidden');
        errorDiv.classList.add('hidden');
        confidenceBar.style.width = '0%';

        // Reset connection dot to cyan (scanning)
        if (connectionDot) {
            connectionDot.style.background = '#00f3ff';
            connectionDot.style.boxShadow  = '0 0 8px #00f3ff';
        }

        authView.classList.add('hidden');

        chrome.runtime.sendMessage({ action: "analyze_current_tab" }, (response) => {
            loader.classList.add('hidden');

            // Handle Chrome runtime errors gracefully
            if (chrome.runtime.lastError) {
                errorDiv.classList.remove('hidden');
                errorMsg.innerText = "Extension error: " + chrome.runtime.lastError.message;
                return;
            }

            if (response && response.status) {
                resultDiv.classList.remove('hidden');
                applyTheme(response.status);

                // Update deep scan features & advanced intel if provided (Analyst/Admin payload)
                if (response.features) {
                    const metricBox = document.querySelector('.metric-box');
                    if (metricBox) metricBox.style.display = 'block';
                    const intelGrid = document.querySelector('.intelligence-grid');
                    if (intelGrid) intelGrid.style.display = 'flex'; // or grid depending on css
                    const featDetails = document.getElementById('feature-details');
                    if (featDetails) featDetails.style.display = 'block';

                    // Animate confidence bar
                    setTimeout(() => {
                        const conf = response.confidence != null ? parseFloat(response.confidence) : 100;
                        confidenceBar.style.width = `${conf}%`;
                        animateValue(confidenceText, 0, conf, 1000);
                    }, 100);

                    updateIntel(response);

                    document.getElementById('feat-len').innerText  = response.features.url_length + ' chars';
                    document.getElementById('feat-at').innerText   = response.features.has_at_symbol ? 'DETECTED' : 'CLEAN';
                    document.getElementById('feat-sub').innerText  = response.features.num_subdomains;
                    document.getElementById('feat-https').innerText = response.features.is_https ? 'HTTPS/SEC' : 'HTTP/INSEC';
                    document.getElementById('feat-dom').innerText  = response.features.suspicious_dom_elements + ' flags';

                    // Color anomalies
                    document.getElementById('feat-at').style.color    = response.features.has_at_symbol ? '#ff003c' : '#39ff14';
                    document.getElementById('feat-https').style.color = response.features.is_https ? '#39ff14' : '#ff003c';
                } else {
                    // RBAC Sanitized Payload (End User)
                    const metricBox = document.querySelector('.metric-box');
                    if (metricBox) metricBox.style.display = 'none';
                    const intelGrid = document.querySelector('.intelligence-grid');
                    if (intelGrid) intelGrid.style.display = 'none';
                    const featDetails = document.getElementById('feature-details');
                    if (featDetails) featDetails.style.display = 'none';
                }

                // Blockchain log indicator
                if (response.logged_to_blockchain) {
                    bcLogged.classList.remove('hidden');
                } else {
                    bcLogged.classList.add('hidden');
                }

            } else {
                // Show error state
                errorDiv.classList.remove('hidden');
                if (connectionDot) {
                    connectionDot.style.background = '#ff003c';
                    connectionDot.style.boxShadow  = '0 0 8px #ff003c';
                }
                let msg = "Backend unreachable. Ensure the backend server is running.";
                if (response && response.error) {
                    if (response.error === "restricted_page")   msg = "Cannot scan Chrome system pages (chrome://).";
                    else if (response.error === "reload_required") msg = "Please reload the web page and try again.";
                    else if (response.error === "api_error")    msg = "AI engine is offline. Start the backend server.";
                    else if (response.error === "no_features")  msg = "Could not extract page features. Try reloading.";
                }
                errorMsg.innerText = msg;
            }
        });
    }

    function updateIntel(response) {
        const intelWhitelist    = document.getElementById('intel-whitelist');
        const intelAge          = document.getElementById('intel-age');
        const intelSafeBrowsing = document.getElementById('intel-safebrowsing');

        // Google Safe Browsing
        const message = response.message || "";
        if (message.includes("Blocked by Google")) {
            intelSafeBrowsing.innerText     = "THREAT_FOUND";
            intelSafeBrowsing.style.color   = '#ff003c';
        } else if (message.includes("API timeout") || message.includes("No API key")) {
            intelSafeBrowsing.innerText     = "SKIPPED";
            intelSafeBrowsing.style.color   = '#ffb000';
        } else {
            intelSafeBrowsing.innerText     = "CLEAN";
            intelSafeBrowsing.style.color   = '#39ff14';
        }

        // Tranco Whitelist
        if (response.is_whitelisted) {
            intelWhitelist.innerText    = "VERIFIED";
            intelWhitelist.style.color  = '#39ff14';
        } else {
            intelWhitelist.innerText    = "UNLISTED";
            intelWhitelist.style.color  = '#ffb000';
        }

        // Domain Age
        const ageDays = response.domain_age_days;
        if (ageDays !== undefined && ageDays !== -1 && ageDays !== null) {
            setAgeDisplay(intelAge, ageDays);
        } else {
            // Async fetch for domain age
            intelAge.innerText      = "FETCHING...";
            intelAge.style.color    = '#00f3ff';
            fetch(`${API_BASE}/domain-age?url=${encodeURIComponent(response.url)}`)
                .then(r => r.json())
                .then(data => setAgeDisplay(intelAge, data.age_days))
                .catch(() => {
                    intelAge.innerText   = "N/A";
                    intelAge.style.color = '#555';
                });
        }
    }

    function setAgeDisplay(el, ageDays) {
        if (ageDays === -1 || ageDays === null || ageDays === undefined) {
            el.innerText   = "UNKNOWN";
            el.style.color = '#555';
        } else if (ageDays < 30) {
            el.innerText   = `${ageDays}d_[WARN]`;
            el.style.color = '#ff003c';
        } else if (ageDays > 365) {
            el.innerText   = `${Math.floor(ageDays / 365)}yr_STABLE`;
            el.style.color = '#39ff14';
        } else {
            el.innerText   = `${ageDays}_DAYS`;
            el.style.color = '#e2e8f0';
        }
    }

    function animateValue(el, start, end, duration) {
        let startTimestamp = null;
        const step = (timestamp) => {
            if (!startTimestamp) startTimestamp = timestamp;
            const progress = Math.min((timestamp - startTimestamp) / duration, 1);
            el.innerHTML = (progress * (end - start) + start).toFixed(1) + '%';
            if (progress < 1) window.requestAnimationFrame(step);
        };
        window.requestAnimationFrame(step);
    }

    // ---- Button event listeners ----

    chrome.storage.local.get(['soc_token'], (res) => {
        if (res.soc_token) {
            analyze();
        } else {
            authView.classList.remove('hidden');
            loader.classList.add('hidden');
        }
    });

    // Logout button (connection dot)
    if (connectionDot) {
        connectionDot.addEventListener('click', () => {
            chrome.storage.local.remove(['soc_token'], () => {
                authView.classList.remove('hidden');
                loader.classList.add('hidden');
                resultDiv.classList.add('hidden');
                errorDiv.classList.add('hidden');
                authModeTitle.innerText = "SOC LOGIN";
                authSubmitBtn.innerText = "AUTHENTICATE";
                authError.classList.add('hidden');
                document.getElementById('auth-username').value = "";
                document.getElementById('auth-password').value = "";
            });
        });
    }

    // Auth Tabs Logic
    tabLogin.addEventListener('click', () => {
        isRegisterMode = false;
        tabLogin.style.background = 'rgba(0,243,255,0.2)';
        tabLogin.style.color = 'var(--cyber-cyan)';
        tabRegister.style.background = 'transparent';
        tabRegister.style.color = 'gray';
        registerFields.classList.add('hidden');
        authModeTitle.innerText = "SOC LOGIN";
        authSubmitBtn.innerText = "AUTHENTICATE";
        authError.classList.add('hidden');
    });

    tabRegister.addEventListener('click', () => {
        isRegisterMode = true;
        tabRegister.style.background = 'rgba(0,243,255,0.2)';
        tabRegister.style.color = 'var(--cyber-cyan)';
        tabLogin.style.background = 'transparent';
        tabLogin.style.color = 'gray';
        registerFields.classList.remove('hidden');
        authModeTitle.innerText = "NEW IDENTITY";
        authSubmitBtn.innerText = "CREATE IDENTITY";
        authError.classList.add('hidden');
    });

    authRole.addEventListener('change', () => {
        const role = authRole.value;
        authWallet.classList.add('hidden');
        authPin.classList.add('hidden');
        if (role === 'Analyst') authWallet.classList.remove('hidden');
        if (role === 'Admin') authPin.classList.remove('hidden');
    });

    authSubmitBtn.addEventListener('click', async () => {
        const username = document.getElementById('auth-username').value;
        const password = document.getElementById('auth-password').value;
        if (!username || !password) return;
        
        authSubmitBtn.innerText = "PROCESSING...";
        authError.classList.add('hidden');

        try {
            if (isRegisterMode) {
                // Register
                const payload = {
                    username,
                    password,
                    role: authRole.value,
                    wallet_id: authWallet.value,
                    admin_pin: authPin.value
                };
                
                const regRes = await fetch(`${API_BASE}/auth/register`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                
                if (!regRes.ok) {
                    const errText = await regRes.text();
                    throw new Error(errText);
                }
            }

            // Login
            const formData = new URLSearchParams();
            formData.append('username', username);
            formData.append('password', password);

            const res = await fetch(`${API_BASE}/auth/token`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: formData
            });

            if (!res.ok) throw new Error("Invalid credentials");
            const data = await res.json();
            
            chrome.storage.local.set({ soc_token: data.access_token }, () => {
                authView.classList.add('hidden');
                analyze();
            });
        } catch (err) {
            authSubmitBtn.innerText = isRegisterMode ? "CREATE IDENTITY" : "AUTHENTICATE";
            authError.innerText = isRegisterMode ? "REGISTRATION FAILED" : "ACCESS DENIED";
            authError.classList.remove('hidden');
        }
    });

    reanalyzeBtn.addEventListener('click', analyze);

    // SOC Dashboard button — opens the React DEV server with token
    dashboardBtn.addEventListener('click', () => {
        chrome.storage.local.get(['soc_token'], (res) => {
            if (res.soc_token) {
                chrome.tabs.create({ url: `http://localhost:5173?token=${res.soc_token}` });
            } else {
                chrome.tabs.create({ url: 'http://localhost:5173' });
            }
        });
    });

    reportBtn.addEventListener('click', () => {
        const originalText   = reportBtn.innerText;
        reportBtn.innerText  = "TRANSMITTING...";
        reportBtn.disabled   = true;

        chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
            const activeTab = tabs[0];
            if (!activeTab || !activeTab.url) {
                reportBtn.innerText = "NO URL FOUND";
                reportBtn.disabled  = false;
                return;
            }

            chrome.storage.local.get(['soc_token'], (res) => {
                const headers = { 'Content-Type': 'application/json' };
                if (res.soc_token) {
                    headers['Authorization'] = `Bearer ${res.soc_token}`;
                }

                fetch(`${API_BASE}/report`, {
                    method: 'POST',
                    headers: headers,
                    body: JSON.stringify({ url: activeTab.url })
                }).then(response => {
                    if (response.ok) {
                        reportBtn.innerText             = "TX_COMMITTED";
                        reportBtn.style.background      = "rgba(57,255,20,0.1)";
                        reportBtn.style.color           = "#39ff14";
                        reportBtn.style.borderColor     = "rgba(57,255,20,0.4)";
                        reportBtn.style.textShadow      = "0 0 8px #39ff14";
                    } else {
                        reportBtn.innerText = "TX_FAILED";
                        reportBtn.disabled  = false;
                    }
                }).catch(() => {
                    reportBtn.innerText = "NET_ERROR";
                    reportBtn.disabled  = false;
                });
            });
        });
    });
});
