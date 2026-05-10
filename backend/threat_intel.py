import os
import httpx

# Google Safe Browsing API v4 URL
SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

def check_safe_browsing(url: str) -> dict:
    """
    Checks the URL against Google Safe Browsing.
    Returns a dictionary with 'is_phishing' boolean and a corresponding message.
    """
    api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
    
    # Elegant fallback if no key is provided (so the project doesn't break for peers/professors)
    if not api_key:
        return {"is_phishing": False, "message": "Google Safe Browsing API key missing. Proceeding to ML."}

    payload = {
        "client": {
            "clientId": "btech-phishing-detector",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            # We are checking for Malware, Social Engineering (Phishing), and Unwanted Software
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": url}
            ]
        }
    }

    try:
        # We use httpx for synchronous requests (can easily be async if FastAPI is completely async)
        with httpx.Client(timeout=3.0) as client:
            response = client.post(f"{SAFE_BROWSING_URL}?key={api_key}", json=payload)
            response.raise_for_status()
            data = response.json()
            
            # If the API returns any matches, the site is flagged as dangerous
            if "matches" in data and len(data["matches"]) > 0:
                threat_type = data["matches"][0]["threatType"]
                return {
                    "is_phishing": True, 
                    "message": f"Blocked by Google Threat Intelligence: {threat_type}"
                }
            
            return {"is_phishing": False, "message": "Cleared by Google Safe Browsing."}

    except Exception as e:
        print(f"Failed to query Google Safe Browsing: {e}")
        # Fail open: if the API is down or config is wrong, just rely on our ML model!
        return {"is_phishing": False, "message": "Google API timeout. Falling back to internal engine."}
