document.addEventListener('DOMContentLoaded', function () {
    const statusText = document.getElementById('status-text');
    const confidenceText = document.getElementById('confidence-text');
    const bcLogged = document.getElementById('bc-logged');
    const loader = document.getElementById('loader');
    const resultDiv = document.getElementById('result');
    const errorDiv = document.getElementById('error');
    const btn = document.getElementById('reanalyze-btn');

    function analyze() {
        loader.classList.remove('hidden');
        resultDiv.classList.add('hidden');
        errorDiv.classList.add('hidden');

        chrome.runtime.sendMessage({ action: "analyze_current_tab" }, (response) => {
            loader.classList.add('hidden');
            if (response && response.status) {
                resultDiv.classList.remove('hidden');
                statusText.innerText = response.status;
                if (response.status === "Phishing") {
                    statusText.style.color = "#ef4444"; // red
                } else if (response.status === "Suspicious") {
                    statusText.style.color = "#f59e0b"; // yellow
                } else {
                    statusText.style.color = "#10b981"; // green
                }

                confidenceText.innerText = `Confidence: ${response.confidence}%`;

                if (response.features) {
                    document.getElementById('feature-details').style.display = 'block';
                    document.getElementById('feat-len').innerText = response.features.url_length;
                    document.getElementById('feat-at').innerText = response.features.has_at_symbol ? "Yes" : "No";
                    document.getElementById('feat-sub').innerText = response.features.num_subdomains;
                    document.getElementById('feat-https').innerText = response.features.is_https ? "Yes" : "No";
                    document.getElementById('feat-dom').innerText = response.features.suspicious_dom_elements;
                } else {
                    document.getElementById('feature-details').style.display = 'none';
                }

                if (response.logged_to_blockchain) {
                    bcLogged.classList.remove('hidden');
                } else {
                    bcLogged.classList.add('hidden');
                }

            } else {
                errorDiv.classList.remove('hidden');
                if (response && response.error) {
                    if (response.error === "restricted_page") {
                        errorDiv.innerText = "Cannot scan restricted Chrome pages. Please test on a real website.";
                    } else if (response.error === "reload_required") {
                        errorDiv.innerText = "Please reload the webpage and try again.";
                    } else if (response.error === "api_error") {
                        errorDiv.innerText = "Failed to connect to backend server. Is FastAPI running?";
                    } else {
                        errorDiv.innerText = "Error analyzing page: " + response.error;
                    }
                } else {
                    errorDiv.innerText = "An unknown error occurred during analysis.";
                }
            }
        });
    }

    analyze();

    btn.addEventListener('click', analyze);

    document.getElementById('dashboard-btn').addEventListener('click', () => {
        chrome.tabs.create({ url: 'http://localhost:5173' });
    });
});
